"""Focused unit test for the Chronicle (UDM Search + YARA-L 2.0) translator.

The pack-level smoke test (`_check_detections_pack.py`) verifies that
every shipped rule compiles. This script complements it by asserting
*shape* — that the emitted expressions actually contain the constructs
we expect for each Sigma feature: equality, contains/startswith/endswith
wildcards, regex modifiers, CIDR, numeric comparisons, list-of-dicts
expansion, condition operators (and/or/not), and YARA-L wrapping with
the ``$<event_var>.`` prefix.

Run directly:

    python tests/_check_chronicle_translator.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from app.detections import (  # noqa: E402
    BackendError,
    SigmaRule,
    translate_chronicle,
    translate_chronicle_yaral,
)


# --------------------------------------------------------------------------- #
# Tiny test harness
# --------------------------------------------------------------------------- #

_PASS = 0
_FAIL: list[str] = []


def _ok(msg: str) -> None:
    global _PASS
    _PASS += 1
    print(f"ok   {msg}")


def _fail(msg: str) -> None:
    _FAIL.append(msg)
    print(f"FAIL {msg}")


def _assert_in(haystack: str, needle: str, label: str) -> None:
    if needle in haystack:
        _ok(f"{label}: contains {needle!r}")
    else:
        _fail(f"{label}: expected {needle!r} in:\n        {haystack}")


def _assert_not_in(haystack: str, needle: str, label: str) -> None:
    if needle not in haystack:
        _ok(f"{label}: omits {needle!r}")
    else:
        _fail(f"{label}: did not expect {needle!r} in:\n        {haystack}")


def _rule(yaml_text: str) -> SigmaRule:
    return SigmaRule.from_yaml(yaml_text)


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #


def case_equality_and_wildcards() -> None:
    r = _rule(
        """
        title: Equality + wildcards
        id: c-equality-01
        status: experimental
        level: high
        logsource: {category: process_creation}
        detection:
          sel:
            Image|endswith: \\\\powershell.exe
            CommandLine|contains: -enc
            User: SYSTEM
          condition: sel
        """
    )
    udm = translate_chronicle(r)
    # endswith wildcard => regex literal with nocase
    _assert_in(udm, "Image = /", "equality+wildcards UDM")
    _assert_in(udm, "nocase", "equality+wildcards UDM")
    # plain equality
    _assert_in(udm, 'User = "SYSTEM" nocase', "equality+wildcards UDM")
    # contains -> wildcard regex (NOT literal "*-enc*")
    _assert_in(udm, "CommandLine = /", "equality+wildcards UDM contains")
    _assert_not_in(udm, '"*-enc*"', "equality+wildcards UDM contains")
    # multiple field clauses joined with ` and `
    _assert_in(udm, " and ", "equality+wildcards UDM conjunction")


def case_regex_and_negation() -> None:
    r = _rule(
        """
        title: Regex + negation
        id: c-regex-02
        status: experimental
        level: medium
        logsource: {category: webserver}
        detection:
          sel:
            uri|re:
              - ^/admin/.*
              - ^/api/v1/secret
          benign:
            user_agent: HealthCheck/1.0
          condition: sel and not benign
        """
    )
    udm = translate_chronicle(r)
    _assert_in(udm, "uri = /^\\/admin\\/.*/ nocase", "regex UDM escape")
    _assert_in(udm, "uri = /^\\/api\\/v1\\/secret/ nocase", "regex UDM escape")
    _assert_in(udm, "not (", "regex UDM negation")
    _assert_in(udm, " or ", "regex UDM or-join")


def case_numeric_comparisons() -> None:
    r = _rule(
        """
        title: Numeric comparisons
        id: c-numeric-03
        status: experimental
        level: medium
        logsource: {category: network}
        detection:
          sel:
            bytes_out|gt: 1000000
            dst_port|lte: 1024
          condition: sel
        """
    )
    udm = translate_chronicle(r)
    _assert_in(udm, "bytes_out > 1000000", "numeric UDM gt")
    _assert_in(udm, "dst_port <= 1024", "numeric UDM lte")
    # Numeric literals must not be quoted
    _assert_not_in(udm, '"1000000"', "numeric UDM unquoted")


def case_cidr() -> None:
    r = _rule(
        """
        title: CIDR ranges
        id: c-cidr-04
        status: experimental
        level: high
        logsource: {category: network}
        detection:
          sel:
            src_ip|cidr:
              - 10.0.0.0/8
              - 192.168.0.0/16
          condition: sel
        """
    )
    udm = translate_chronicle(r)
    _assert_in(udm, 'net.ip_in_range_cidr(src_ip, "10.0.0.0/8")', "cidr UDM")
    _assert_in(udm, 'net.ip_in_range_cidr(src_ip, "192.168.0.0/16")', "cidr UDM")


def case_list_of_dicts_and_quantifier() -> None:
    r = _rule(
        """
        title: List-of-dicts + 1 of selection*
        id: c-listofdicts-05
        status: experimental
        level: high
        logsource: {category: process_creation}
        detection:
          selection_powershell:
            - Image|endswith: \\\\powershell.exe
              CommandLine|contains: -nop
            - Image|endswith: \\\\pwsh.exe
              CommandLine|contains: -enc
          selection_cmd:
            Image|endswith: \\\\cmd.exe
          condition: 1 of selection_*
        """
    )
    udm = translate_chronicle(r)
    # list-of-dicts expands to OR of grouped clauses
    _assert_in(udm, " or ", "list-of-dicts UDM or")
    _assert_in(udm, "Image = /", "list-of-dicts UDM regex")
    _assert_in(udm, "CommandLine = /", "list-of-dicts UDM regex")
    # Top-level "1 of" reads as OR across selections
    head, _, _ = udm.rpartition(")")
    if udm.startswith("(") and udm.endswith(")") and " or " in udm:
        _ok("list-of-dicts UDM quantifier OR")
    else:
        _fail(f"list-of-dicts UDM quantifier OR: {udm}")


def case_exists_and_null() -> None:
    r = _rule(
        """
        title: Field existence + explicit null
        id: c-exists-06
        status: experimental
        level: low
        logsource: {category: process_creation}
        detection:
          present:
            ParentImage|exists: true
          missing:
            CommandLine: null
          condition: present and missing
        """
    )
    udm = translate_chronicle(r)
    _assert_in(udm, 'ParentImage != ""', "exists UDM present")
    _assert_in(udm, 'CommandLine = ""', "exists UDM null/empty")


def case_yaral_wrapping() -> None:
    r = _rule(
        """
        title: YARA-L wrapping check
        id: c-yaral-07
        status: experimental
        level: critical
        logsource: {category: process_creation}
        tags:
          - attack.execution
          - attack.t1059
        detection:
          sel:
            Image|endswith: \\\\powershell.exe
            CommandLine|contains: -enc
          condition: sel
        """
    )
    yara = translate_chronicle_yaral(r)
    first_line = yara.split("\n", 1)[0]
    if first_line.startswith("rule ") and first_line.endswith("{"):
        _ok(f"YARA-L header: {first_line}")
    else:
        _fail(f"YARA-L header malformed: {first_line!r}")

    for required in (
        "meta:",
        "events:",
        "condition:",
        'author = "aisoc"',
        'severity = "CRITICAL"',
        'rule_id = "c-yaral-07"',
        '"attack.execution"',
        '"attack.t1059"',
        "$e.Image = /",
        "$e.CommandLine = /",
        "$e",
    ):
        _assert_in(yara, required, "YARA-L body")

    # Plain UDM Search version must NOT carry the $e. prefix
    udm = translate_chronicle(r)
    _assert_not_in(udm, "$e.", "UDM has no event-var prefix")


def case_yaral_id_sanitization() -> None:
    # IDs with disallowed chars (dots, dashes, slashes) must be
    # sanitized into a valid YARA-L identifier.
    r = _rule(
        """
        title: ID needs sanitizing
        id: 7f0c2a44-bb91-4d2d-9bf3-1ad9e2a08c5f
        status: experimental
        level: medium
        logsource: {category: process_creation}
        detection:
          sel:
            Image|endswith: \\\\rundll32.exe
          condition: sel
        """
    )
    yara = translate_chronicle_yaral(r)
    first_line = yara.split("\n", 1)[0]
    # Header must be `rule <ident> {` with an identifier whose first
    # char is a letter and that contains no '-' or '.'.
    if not first_line.startswith("rule "):
        _fail(f"id-sanitize header missing 'rule ': {first_line!r}")
        return
    ident = first_line[len("rule ") :].rstrip(" {").strip()
    if "-" in ident or "." in ident:
        _fail(f"id-sanitize identifier still has bad chars: {ident!r}")
    elif not ident or not ident[0].isalpha():
        _fail(f"id-sanitize identifier must start with a letter: {ident!r}")
    else:
        _ok(f"id-sanitize produced valid identifier: {ident}")


def case_unsupported_raises() -> None:
    # The translator surfaces unsupported AST nodes loudly so the
    # GitOps pipeline catches them before publishing.
    class _Bogus:
        pass

    rule = _rule(
        """
        title: Will-be-mutated
        id: c-bogus-08
        status: experimental
        level: low
        logsource: {category: process_creation}
        detection:
          sel: {Image: foo.exe}
          condition: sel
        """
    )
    # Replace the parsed condition with something the translator
    # has never seen before. This catches the "fail closed" path.
    rule.condition = _Bogus()  # type: ignore[assignment]
    try:
        translate_chronicle(rule)
    except BackendError as exc:
        _ok(f"unsupported node raises BackendError: {exc}")
    else:
        _fail("unsupported node did not raise BackendError")


def main() -> int:
    for fn in (
        case_equality_and_wildcards,
        case_regex_and_negation,
        case_numeric_comparisons,
        case_cidr,
        case_list_of_dicts_and_quantifier,
        case_exists_and_null,
        case_yaral_wrapping,
        case_yaral_id_sanitization,
        case_unsupported_raises,
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            _fail(f"{fn.__name__} crashed: {exc!r}")

    print()
    if _FAIL:
        print(f"FAIL chronicle translator: {len(_FAIL)} failure(s), {_PASS} ok")
        for f in _FAIL:
            print(f"  - {f}")
        return 1
    print(f"PASS chronicle translator ({_PASS} assertions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
