"""The signed, redacted artefact a design partner sends back.

Phase 1.5. `make replay-eval` runs a replay on the partner's own host and
writes one of these. It is the only thing that leaves their estate, so the
whole module is organised around one question: what is in a replay result
that a partner would not want to publish?

The answer is not "the item rows", which is the assumption that makes this
dangerous. Three fields in the **aggregate** carry free text lifted
verbatim from the partner's environment:

* ``per_rule[].key`` — their detection rule names, which describe their
  coverage and often their internal naming scheme;
* ``per_source[].key`` — the products they run;
* ``hallucinated_examples`` — indicator strings pulled out of the agent's
  own reasoning, so hostnames, internal domains and addresses, selected
  precisely because they looked like indicators.

So "aggregate only" is not a privacy control by itself, and a redaction
pass that ran only over exported items would have shipped all three. The
pass runs over everything, always, with no flag to disable it: the partner
already holds the unredacted report in their own API, and a bundle is by
definition the copy that travels.

Two passes, because the fields need different treatment and running one
over both would be wrong in both directions.

**Identifiers are replaced whole.** A rule name, a source name and a
finding id are each *entirely* an identifier, so they become ``RULE_1``,
``SOURCE_1``, ``FINDING_1``. Nothing is pattern-matched inside them. This
matters: :class:`Pseudonymizer` redacts hostnames only as FQDNs under an
internal suffix, so a rule named ``Suspicious PowerShell on FIN-DB-01``
passes through it unchanged, and rule names are full of bare short
hostnames, team names and internal project codenames. Tokenising the
whole value cannot miss a pattern because it matches no patterns.

**Free text is pattern-redacted**, because the agent's reasoning is the
thing a maintainer needs in order to tell a wrong verdict from a right
verdict reached for a wrong reason, and replacing it whole would leave
nothing to read. That pass is :class:`Pseudonymizer` — the same module
triage uses before it sends evidence to a hosted model, not a second
redactor written for this format — preceded by a literal substitution of
every identifier already tokenised, so a host named in a rule carries the
same token where it appears in the reasoning.

The limits of the second pass are stated in the bundle itself rather than
implied. It catches email addresses, internal FQDNs, private addresses,
filesystem paths and down-level logon names. It does not catch a bare
short hostname that appears nowhere but in prose, and it deliberately
keeps public domains and addresses, which are indicators rather than the
partner's property. A privacy note that overstated this would be worse
than none, because it is read by someone deciding what to send.

Both passes are reversible *locally*: the maps stay in the process that
built the bundle and are never written into it, so ``HOST_2`` is stable
within one bundle and meaningless outside it, and a reader can see that
two rows concern one host without learning which.

Signing is :func:`app.services.evidence_bundle.sign_envelope`, the same
integrity block an investigation bundle carries, so one verifier reads
both and a signature cannot be computed over a different serialisation
than the one checked.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from app._vendor.redactor import Pseudonymizer
from app.services.evidence_bundle import sign_envelope

__all__ = [
    "REPLAY_BUNDLE_SCHEMA_VERSION",
    "BundleRedactor",
    "ReplayBundleError",
    "build_replay_bundle",
    "redact_aggregate",
    "redact_items",
    "replay_bundle_filename",
]

#: This format's own version. Bumped when the payload shape changes in a
#: way a reader must notice.
REPLAY_BUNDLE_SCHEMA_VERSION = "1.0"

#: Dropped from an exported item rather than pseudonymized. `evidence` is
#: the whole alert body triage reasoned over — raw vendor fields, command
#: lines, file paths, request bodies. Pseudonymizing free-form vendor JSON
#: means trusting a regex set to have seen every shape a vendor emits, and
#: the honest answer is that it has not. The grading-relevant facts are
#: already in the verdict, the label and the confidence beside it.
_DROPPED_ITEM_FIELDS = frozenset({"evidence"})

#: Item fields carrying free text the agent wrote. Pseudonymized, not
#: dropped: the reasoning is the thing a maintainer needs in order to tell
#: a wrong verdict from a right verdict reached for a wrong reason.
_FREE_TEXT_ITEM_FIELDS = ("findings", "confidence_basis")

#: Item fields that identify a row in the partner's SIEM, and the token
#: kind each takes. Replaced whole, so two rows under one rule still group,
#: which is what makes an exported item set re-derivable into the same
#: confusion matrix.
_IDENTIFIER_ITEM_FIELDS = {"finding_id": "FINDING", "rule_id": "RULE"}

#: Aggregate segments keyed on partner-derived names, and the token kind
#: each takes. `per_rule` shares the `RULE` kind with the item field, so a
#: rule is the same token in the breakdown and in the rows behind it.
_AGGREGATE_SEGMENTS = {"per_rule": "RULE", "per_source": "SOURCE"}


#: A word shaped like an internal host: alphanumeric segments joined by
#: hyphens, with at least one digit somewhere. `FIN-DB-01`, `web-03` and
#: `ip-10-2-3-4` match; `PowerShell`, `Suspicious` and `multi-factor` do
#: not, because a pattern that rewrote ordinary words in the agent's
#: reasoning would damage the thing the reasoning is exported for.
#:
#: Deliberately narrow, and deliberately not presented as complete: a host
#: named `atlas` is indistinguishable from a noun and is not matched. The
#: bundle's privacy block says so.
_HOST_SHAPED_RE = re.compile(r"\b(?=[A-Za-z0-9-]*\d)[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+\b")

#: Leading segments that make a host-shaped match public taxonomy rather
#: than a machine. `SHA-256`, `CVE-2026-1234`, `RFC-1918` and `AES-256` all
#: match the host shape and all must survive: they are the vocabulary the
#: agent reasons in, and a bundle whose reasoning says `HOST_4 hashing`
#: instead of `SHA-256 hashing` has been made unreadable to protect
#: nothing. Compared case-insensitively against the match's first segment.
_PUBLIC_TAXONOMY_PREFIXES = frozenset(
    {
        "aes",
        "arm",
        "base",
        "cve",
        "cwe",
        "capec",
        "des",
        "ec",
        "gmt",
        "hmac",
        "http",
        "https",
        "ieee",
        "iso",
        "md",
        "nist",
        "rfc",
        "rsa",
        "sha",
        "ssl",
        "tls",
        "utc",
        "utf",
        "x86",
    }
)

#: Minimum length for an identifier to be substituted back into free text.
#: Below this the literal is as likely to be a word as a name — a rule id of
#: ``s3`` would rewrite every mention of the service — and the substitution
#: would damage the reasoning it exists to preserve.
_MIN_SUBSTITUTABLE_LENGTH = 4


class ReplayBundleError(RuntimeError):
    """A bundle could not be built. Carries why, never just None."""


def _utc_iso(value: datetime | None = None) -> str:
    moment = value or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat()


class BundleRedactor:
    """The two passes, sharing one map so tokens agree across sections.

    One instance per bundle. A per-section instance would emit three
    tokens for one host and destroy exactly the structure an export exists
    to preserve: that two rows concern the same thing.
    """

    def __init__(self, *, tenant_id: str = "") -> None:
        self._pseudonymizer = Pseudonymizer(tenant_id=tenant_id)
        self._identifiers: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}

    def identifier(self, kind: str, value: object) -> str:
        """Replace a whole identifier with a stable token.

        Matches nothing inside the value, so it cannot miss a pattern.

        Host-shaped words *inside* the value are additionally registered
        for the free-text pass. A rule named ``Suspicious PowerShell on
        FIN-DB-01`` otherwise leaves ``FIN-DB-01`` readable everywhere the
        agent mentions it, because substituting the whole rule name cannot
        match the bare host inside a sentence, and the pattern redactor
        sees hostnames only as FQDNs under an internal suffix.
        """
        text = str(value)
        if not text:
            return text
        key = (kind, text)
        token = self._identifiers.get(key)
        if token is None:
            self._counters[kind] = self._counters.get(kind, 0) + 1
            token = f"{kind}_{self._counters[kind]}"
            self._identifiers[key] = token
            for host in _HOST_SHAPED_RE.findall(text):
                if host != text:
                    self.identifier("HOST", host)
        return token

    def free_text(self, value: object) -> str:
        """Pattern-redact prose, after substituting identifiers already seen.

        Longest literal first, so a rule named ``FIN-DB-01 lateral`` is
        replaced before the host ``FIN-DB-01`` it contains and the result
        is not a token glued to a fragment of the longer name.
        """
        text = str(value)
        if not text:
            return text
        known = sorted(
            ((literal, token) for (_, literal), token in self._identifiers.items() if len(literal) >= _MIN_SUBSTITUTABLE_LENGTH),
            key=lambda pair: len(pair[0]),
            reverse=True,
        )
        for literal, token in known:
            text = text.replace(literal, token)
        text = self._redact_bare_hosts(text)
        return self._pseudonymizer.redact(text)

    def _redact_bare_hosts(self, text: str) -> str:
        """Replace host-shaped tokens the identifier pass never saw.

        The agent's own reasoning quotes machine names it pulled out of the
        event — ``Extracted 2 IOCs: ['198.51.100.7', 'WS-040']`` — and those
        names appear in no identifier field, so nothing registered them. The
        pseudonymizer below only rewrites qualified domain names, which a
        bare NetBIOS-style name is not. This is the leak a real partner
        bundle hits first, so the shape is matched directly here.

        Matches resolving to public taxonomy are left alone: see
        ``_PUBLIC_TAXONOMY_PREFIXES``.
        """

        def substitute(match: re.Match[str]) -> str:
            literal = match.group(0)
            head = re.split(r"[-_.]", literal, maxsplit=1)[0].lower()
            if head in _PUBLIC_TAXONOMY_PREFIXES:
                return literal
            # "HOST" exactly: the kind string is the counter's namespace, so
            # a lowercase spelling here would give the same machine two
            # different tokens depending on whether an identifier field or a
            # sentence mentioned it first, and the bundle would stop being
            # joinable across its own rows.
            return self.identifier("HOST", literal)

        return _HOST_SHAPED_RE.sub(substitute, text)


def redact_aggregate(score: Mapping[str, Any], redactor: BundleRedactor, *, include_examples: bool = False) -> dict[str, Any]:
    """Redact the three aggregate fields carrying partner-derived text.

    Everything else in a score is a number, a count or a term from this
    repository's own fixed vocabulary, and is copied through unchanged. A
    pass that redacted every string would rewrite the class labels and the
    confusion-matrix axes, and a report whose classes read ``TOKEN_4``
    grades nothing.
    """
    redacted = dict(score)

    for segment, kind in _AGGREGATE_SEGMENTS.items():
        rows = redacted.get(segment)
        if not isinstance(rows, list):
            continue
        redacted[segment] = [
            {**row, "key": redactor.identifier(kind, row.get("key", ""))} if isinstance(row, Mapping) else row for row in rows
        ]

    # `hallucinated_examples` is item-level detail that leaked into the
    # aggregate: a list of indicator strings pulled out of the agent's
    # reasoning, selected *because* they looked like hostnames, domains and
    # addresses. The rate, the numerator and the denominator beside it carry
    # the whole analytic value for a reader of a shared artefact, so the
    # strings are withheld unless the partner is exporting item detail
    # anyway. They remain in the partner's own unredacted report.
    if "hallucinated_examples" in redacted:
        if include_examples:
            redacted["hallucinated_examples"] = [redactor.free_text(item) for item in redacted["hallucinated_examples"]]
        else:
            count = len(redacted["hallucinated_examples"]) if isinstance(redacted["hallucinated_examples"], list) else 0
            redacted["hallucinated_examples"] = []
            redacted["hallucinated_examples_withheld"] = count
            redacted["hallucinated_examples_note"] = (
                f"{count} example indicator(s) withheld. They are substrings of the agent's reasoning about your "
                f"estate, and no pattern set de-identifies free text reliably. The rate and its two counts are "
                f"above; the examples are in your own report. Export item detail to include them."
            )

    return redacted


def redact_items(decisions: Sequence[Mapping[str, Any]], redactor: BundleRedactor) -> list[dict[str, Any]]:
    """One redacted row per decision, re-derivable into the same matrix.

    Keeps every field the scorer reads — the label, the verdict, the
    confidence, whether it errored — so a maintainer handed only this can
    recompute the aggregate and get the number in the same bundle. That
    property is what makes an export worth asking for; a row stripped to
    the point where the score cannot be checked is just a smaller leak.
    """
    rows: list[dict[str, Any]] = []
    for decision in decisions:
        row = {key: value for key, value in decision.items() if key not in _DROPPED_ITEM_FIELDS}

        for field, kind in _IDENTIFIER_ITEM_FIELDS.items():
            if row.get(field) is not None:
                row[field] = redactor.identifier(kind, row[field])

        for field in _FREE_TEXT_ITEM_FIELDS:
            value = row.get(field)
            if isinstance(value, list):
                row[field] = [redactor.free_text(item) for item in value]
            elif isinstance(value, str):
                row[field] = redactor.free_text(value)

        # An error string is a stack-adjacent message that can quote a host
        # or a URL. Kept, because "this row errored" is load-bearing for
        # reading the counts, and redacted for the same reason the
        # reasoning is.
        if isinstance(row.get("error"), str):
            row["error"] = redactor.free_text(row["error"])

        row["evidence_withheld"] = True
        rows.append(row)
    return rows


def _redact_method(method: Mapping[str, Any], redactor: BundleRedactor) -> dict[str, Any]:
    """The method note, with the free text it carries redacted.

    `history.connector_type` is a connector id from this repository's own
    registry and stays readable — a bundle that hid which product was read
    could not be interpreted at all. `tenant_id` and `connector_id` are
    this deployment's own UUIDs and become tokens, because a bundle that
    travels should not name the instance it came from.
    """
    redacted = dict(method)

    for field, kind in (("tenant_id", "TENANT"), ("connector_id", "CONNECTOR")):
        if redacted.get(field):
            redacted[field] = redactor.identifier(kind, redacted[field])

    unread = redacted.get("frozen_context_unread")
    if isinstance(unread, list):
        redacted["frozen_context_unread"] = [redactor.free_text(item) for item in unread]

    return redacted


def build_replay_bundle(
    *,
    score: Mapping[str, Any],
    method: Mapping[str, Any],
    model: Mapping[str, Any],
    signing_key: str,
    items: Sequence[Mapping[str, Any]] | None = None,
    evaluation_id: str | uuid.UUID | None = None,
    generated_at: datetime | None = None,
    tenant_id: str = "",
) -> dict[str, Any]:
    """Assemble, redact and sign one replay result.

    `items` is absent by default. Passing it is the partner's explicit
    choice to export per-decision detail; it is redacted either way, so
    the flag controls volume rather than whether the pass ran.

    A pure function of what it is handed: nothing here reads a database or
    an environment, which is what lets a test build one without a
    deployment and lets two exports of one run agree byte for byte.
    """
    if not score:
        raise ReplayBundleError("refusing to build a bundle with no score: an empty aggregate would publish as a run that graded nothing")

    # One redactor for the whole bundle, so a host appearing in a rule name,
    # in the reasoning and in an item row is the same token in all three.
    redactor = BundleRedactor(tenant_id=tenant_id)

    # Identifiers first. `redact_aggregate` registers every rule and source
    # name, so the free-text passes that follow can substitute them before
    # falling back to pattern matching.
    scores = redact_aggregate(score, redactor, include_examples=items is not None)
    redacted_items = redact_items(items, redactor) if items is not None else None

    payload: dict[str, Any] = {
        "bundle_schema_version": REPLAY_BUNDLE_SCHEMA_VERSION,
        "kind": "replay_evaluation",
        "evaluation_id": str(evaluation_id) if evaluation_id else None,
        "generated_at": _utc_iso(generated_at),
        "model": dict(model),
        "scores": scores,
        "method": _redact_method(method, redactor),
        "privacy": {
            "identifiers": "replaced whole with stable tokens (RULE_n, SOURCE_n, FINDING_n, TENANT_n, CONNECTOR_n)",
            "free_text": "pattern-redacted by app._vendor.redactor.Pseudonymizer, after substituting known identifiers",
            "free_text_catches": [
                "email addresses",
                "FQDNs under an internal suffix",
                "private IPv4 addresses",
                "Windows, UNC and multi-segment unix paths",
                "down-level logon names (DOMAIN\\user)",
            ],
            "free_text_does_not_catch": [
                "a single-word machine name carrying no digit and no separator, which is indistinguishable from an ordinary word",
                "a name whose leading segment collides with public taxonomy, such as a host literally named sha-1",
                "public domains and addresses, kept deliberately because they are indicators rather than your property",
            ],
            "reversible_locally": True,
            "mapping_exported": False,
            "mapping_note": (
                "Tokens are stable within this bundle and meaningless outside it. The map lives only in "
                "the process that produced the bundle and is never written to it, so two rows can be seen "
                "to concern one host without that host being named."
            ),
            "evidence_included": False,
            "evidence_note": (
                "Per-decision `evidence` is dropped rather than redacted. It is free-form vendor JSON, "
                "and redacting it would mean trusting a pattern set to have seen every shape a vendor emits."
            ),
            "items_included": items is not None,
        },
    }

    if redacted_items is not None:
        payload["items"] = redacted_items

    return {
        "payload": payload,
        # Outside the payload: a signature cannot cover itself.
        "integrity": sign_envelope(payload, signing_key=signing_key),
    }


def replay_bundle_filename(evaluation_id: str | uuid.UUID) -> str:
    """A stable name, so two exports of one run overwrite rather than accumulate."""
    return f"aisoc-replay-{evaluation_id}.bundle.json"
