import pytest
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


@pytest.mark.parametrize(
    ("operator", "value", "expected"),
    [
        ("eq", "alice", 'user.name == "alice"'),
        ("ne", "alice", 'user.name != "alice"'),
        ("contains", "ali", 'user.name contains "ali"'),
        ("starts_with", "ali", 'user.name startswith "ali"'),
        ("ends_with", "ice", 'user.name endswith "ice"'),
        ("gt", 10, "user.name > 10"),
        ("gte", 10, "user.name >= 10"),
        ("lt", 10, "user.name < 10"),
        ("lte", 10, "user.name <= 10"),
        ("in", ["alice", "bob"], 'user.name in ("alice", "bob")'),
    ],
)
def test_kql_translator_renders_every_supported_operator(operator, value, expected):
    q = UnifiedQuery(
        indicators=(
            Indicator(
                field="user.name",
                operator=operator,
                value=value,
            ),
        ),
    )

    kql = to_kql(q)

    assert expected in kql


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "user.enabled == true"),
        (False, "user.enabled == false"),
        (42, "event.count == 42"),
        (3.14, "event.score == 3.14"),
        ('alice "admin"', 'message == "alice \\"admin\\""'),
        ("C:\\Temp\\tool.exe", 'process.path == "C:\\\\Temp\\\\tool.exe"'),
    ],
)
def test_kql_translator_quotes_values_through_public_renderer(value, expected):
    field = "user.enabled"
    if isinstance(value, int) and not isinstance(value, bool):
        field = "event.count"
    elif isinstance(value, float):
        field = "event.score"
    elif isinstance(value, str) and "\\" in value:
        field = "process.path"
    elif isinstance(value, str):
        field = "message"

    q = UnifiedQuery(
        indicators=(
            Indicator(
                field=field,
                operator="eq",
                value=value,
            ),
        ),
    )

    kql = to_kql(q)

    assert expected in kql


def test_kql_translator_renders_exact_pipeline_order():
    q = UnifiedQuery(
        free_text="kerberoasting",
        indicators=(
            Indicator(
                field="user.name",
                operator="eq",
                value="alice@example.com",
            ),
            Indicator(
                field="source.ip",
                operator="eq",
                value="10.0.0.5",
            ),
        ),
        since_seconds=900,
        limit=50,
    )

    kql = to_kql(q, table="SigninLogs")

    assert kql.splitlines() == [
        "SigninLogs",
        "| where TimeGenerated > ago(900s)",
        '| where * contains "kerberoasting"',
        '| where UserPrincipalName == "alice@example.com"',
        '| where source.ip == "10.0.0.5"',
        "| take 50",
    ]


def test_kql_translator_aliases_only_apply_to_indicator_fields_not_free_text():
    q = UnifiedQuery(
        free_text="user.name",
        indicators=(
            Indicator(
                field="user.name",
                operator="eq",
                value="alice@example.com",
            ),
        ),
    )

    kql = to_kql(q, table="SigninLogs")
    lines = kql.splitlines()

    assert '| where * contains "user.name"' in lines
    assert '| where UserPrincipalName == "alice@example.com"' in lines


def test_kql_translator_commonsecuritylog_unknown_canonical_fields_pass_through():
    q = UnifiedQuery(
        indicators=(
            Indicator(
                field="host.name",
                operator="eq",
                value="host01",
            ),
            Indicator(
                field="source.ip",
                operator="eq",
                value="10.0.0.5",
            ),
            Indicator(
                field="process.name",
                operator="contains",
                value="powershell",
            ),
            Indicator(
                field="event.code",
                operator="in",
                value=[4624, 4625],
            ),
        ),
    )

    kql = to_kql(q, table="CommonSecurityLog")

    assert 'host.name == "host01"' in kql
    assert 'source.ip == "10.0.0.5"' in kql
    assert 'process.name contains "powershell"' in kql
    assert "event.code in (4624, 4625)" in kql
