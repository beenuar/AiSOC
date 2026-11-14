#!/usr/bin/env python3
"""The rest of parity 6.10: OTLP logs, a Kafka input, and a TAXII 2.1 server.

Depth plan 4.2. The syslog bullet has its own gate
(``check_syslog_listener.py``); this one covers the three that were open.
All three are the same shape of claim — an input a third party points at —
and all three fail in the same three ways:

**Unwired.** A package that decodes OTLP perfectly and is constructed by
nothing is indistinguishable from a feature until someone traces the call
graph. The receiver must be constructed, routed and named by ``/readyz``;
the Kafka source must be constructed *and* started.

**Tenant from the payload.** None of these transports carries an
authenticated principal. An OTLP resource attribute, a Kafka record header
and a TAXII URL segment are all set by the caller, so a tenant read from
any of them is a cross-tenant write with no attacker effort at all.

**A loop that cannot tell permanent from transient.** The Kafka input is a
long-lived consumer, and this repository has shipped both halves of that
defect: a consumer that exits into a 200, and one that retries an
unreachable broker forever in silence. It must use the shared
``streamhealth`` table rather than a second copy of it, and it must wire
``ErrorLogger`` — with a ``GroupID`` set, every dial, join and rebalance
failure goes only there while the fetch stays blocked.

Parsed with ``ast`` and plain text rather than by running Go or standing up
Postgres, because this runs in the lint job where neither is available —
and a gate that skips when it cannot find a toolchain is a gate that
silently stops checking.

Usage:
    python3 scripts/check_standard_inputs.py
    python3 scripts/check_standard_inputs.py --self-test
"""

from __future__ import annotations

import argparse
import ast
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import TREE_SHAPES, refuses_an_empty_tree, repo_root  # noqa: E402

REPO_ROOT = repo_root()

OTLP_PKG = Path("services/ingest/internal/otlp")
KAFKA_PKG = Path("services/ingest/internal/kafkainput")
STREAMHEALTH_PKG = Path("services/ingest/internal/streamhealth")
MAIN_GO = Path("services/ingest/main.go")
SERVER_GO = Path("services/ingest/internal/server/server.go")
TEMPLATE_DIR = Path("services/ingest/internal/normalizer/templates")
INBOX_ENDPOINT = Path("services/api/app/api/v1/endpoints/inbox.py")

TAXII_SERVICE = Path("services/api/app/services/taxii.py")
TAXII_ENDPOINT = Path("services/api/app/api/v1/endpoints/taxii.py")
TAXII_MIGRATION = Path("services/api/migrations/113_taxii_collections.sql")
API_ROUTER = Path("services/api/app/api/v1/router.py")

#: The template the OTLP receiver projects through. Named here rather than
#: read out of the receiver, because deriving it would make the gate agree
#: with whatever the receiver happens to say.
OTLP_TEMPLATE = "otlp-logs"

#: Every route a stock TAXII 2.1 client walks. A server missing any one of
#: them is not a TAXII server: the client cannot discover the API root,
#: cannot enumerate collections, or cannot page.
TAXII_ROUTES = (
    "/",
    "/{api_root}/",
    "/{api_root}/collections/",
    "/{api_root}/collections/{collection_ref}/",
    "/{api_root}/collections/{collection_ref}/objects/",
    "/{api_root}/collections/{collection_ref}/manifest/",
)

#: The three failure classes a long-lived consumer has to distinguish. Two
#: is the defect: without the poison class, one undecodable record backs
#: off a subscription that is demonstrably working.
FAILURE_CLASSES = ("ClassTransient", "ClassPermanent", "ClassPoison")


def _read(root: Path, rel: Path) -> str:
    try:
        return (root / rel).read_text(encoding="utf-8")
    except OSError:
        return ""


def _go_sources(root: Path, pkg: Path) -> str:
    directory = root / pkg
    if not directory.is_dir():
        return ""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in sorted(directory.glob("*.go")) if not p.name.endswith("_test.go")
    )


def _strip_go_comments(source: str) -> str:
    """Comments out, so a gate does not match its own explanation.

    Every one of these packages documents in prose *why* the tenant does
    not come from a header or an attribute, quoting the very identifiers
    this gate forbids. A checker that cannot tell code from prose about the
    code fires on the documentation.
    """
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return "\n".join(re.sub(r"//.*$", "", line) for line in source.splitlines())


def _strip_py_comments_and_docstrings(source: str) -> str:
    """Same reasoning, for Python.

    Docstrings are stripped as well as ``#`` comments: the TAXII module's
    own docstring explains the tenant rule by naming the thing it refuses
    to read.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    spans: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            if node.lineno and node.end_lineno:
                spans.append((node.lineno, node.end_lineno))
    drop = {line for start, end in spans for line in range(start, end + 1)}
    kept = [re.sub(r"#.*$", "", line) for number, line in enumerate(source.splitlines(), start=1) if number not in drop]
    return "\n".join(kept)


def _mintable_ids(root: Path) -> set[str]:
    source = _read(root, INBOX_ENDPOINT)
    if not source:
        return set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "ALLOWED_TEMPLATE_IDS" and isinstance(node.value, ast.Tuple):
                return {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


# ---------------------------------------------------------------------------
# OTLP
# ---------------------------------------------------------------------------


def _check_otlp(root: Path, main_go: str, failures: list[str]) -> None:
    sources = _go_sources(root, OTLP_PKG)
    if not sources.strip():
        failures.append(
            f"no Go sources under {OTLP_PKG}. An estate running an OpenTelemetry Collector has a logs "
            f"pipeline and an exporter and nowhere to point it."
        )
        return
    code = _strip_go_comments(sources)

    # Both encodings. A receiver that reads one of them is a receiver half
    # the estates cannot use, and the one it refuses is whichever the
    # collector in front of it happens to be configured for.
    #
    # Matched against a `case` arm rather than anywhere in the file. The
    # first cut of this rule looked for the bare media type and missed a
    # receiver that had stopped accepting JSON entirely, because the
    # string survived in two error messages telling the caller which
    # encodings are supported — a gate reading the apology instead of the
    # behaviour.
    for media, label in (("application/x-protobuf", "protobuf"), ("application/json", "JSON")):
        if not re.search(rf'case[^\n]*"{re.escape(media)}"', code):
            failures.append(
                f"{OTLP_PKG} does not accept {media} in its content-type switch. OTLP/HTTP defines both "
                f"encodings and real collectors emit both, so reading only one leaves {label} senders with "
                f"a 415 they cannot fix."
            )

    if "gzip" not in code:
        failures.append(
            f"{OTLP_PKG} does not decompress gzip. The stock OTLP exporter compresses by default, so an "
            f"uncompressed-only receiver refuses the common case."
        )

    # The partial-success contract. A blanket 200 tells a collector that
    # records it never delivered have landed.
    if "PartialSuccess" not in code:
        failures.append(
            f"{OTLP_PKG} never sets PartialSuccess. A batch that was partly unprojectable then answers a "
            f"blanket 200, which tells the collector records it never delivered have landed."
        )

    if "StatusServiceUnavailable" not in code or "Retry-After" not in code:
        failures.append(
            f"{OTLP_PKG} does not answer 503 with Retry-After when the publish fails. The collector's queue "
            f"is what holds those records; a 200 throws them away and a 400 makes it discard them as invalid."
        )

    # Tenant from the credential, not from an attribute the emitter sets.
    for forbidden in ("resourceAttrs", "scopeAttrs", "payload"):
        if re.search(rf"[Tt]enant\w*\s*:?=\s*[^\n]*\b{forbidden}\b", code):
            failures.append(
                f"{OTLP_PKG} derives the tenant from {forbidden}, which the emitter sets. Every attribute on "
                f"an OTLP record is caller-controlled, so that is a cross-tenant write any instrumented "
                f"process could perform."
            )
    if "tok.TenantID" not in code:
        failures.append(
            f"{OTLP_PKG} does not read the tenant from the resolved token. OTLP has no notion of a tenant, "
            f"so the token is the only thing in the request a sender does not control."
        )

    # Wired: routed, constructed, named by readiness.
    server_go = _strip_go_comments(_read(root, SERVER_GO))
    if not re.search(r'r\.Post\(\s*"/logs"', server_go):
        failures.append(
            f"{SERVER_GO} does not route POST /v1/logs. The path is fixed by OTLP/HTTP - an exporter appends "
            f"/v1/logs to its endpoint - so a receiver mounted anywhere else is unreachable by a stock collector."
        )
    if "otlp.New(" not in main_go:
        failures.append(
            f"{MAIN_GO} never calls otlp.New, so the receiver is constructed by nothing and the route, if any, serves a nil handler."
        )
    if not re.search(r'RegisterSubscription\(\s*"otlp_logs"', main_go):
        failures.append(
            f"{MAIN_GO} does not name the OTLP receiver in /readyz. A receiver nobody is exporting to and one "
            f"refusing every request look identical from outside unless readiness says which."
        )

    # The template it projects through has to exist and be mintable, or the
    # operator cannot create a token the receiver will accept.
    if not (root / TEMPLATE_DIR / f"{OTLP_TEMPLATE}.yaml").is_file():
        failures.append(
            f"{TEMPLATE_DIR}/{OTLP_TEMPLATE}.yaml is missing, so every OTLP record is refused with 'this build has no template'."
        )
    mintable = _mintable_ids(root)
    if mintable and OTLP_TEMPLATE not in mintable:
        failures.append(
            f"'{OTLP_TEMPLATE}' is not in ALLOWED_TEMPLATE_IDS in {INBOX_ENDPOINT}, so no operator can mint a "
            f"token the OTLP receiver will accept and the endpoint refuses every export."
        )


# ---------------------------------------------------------------------------
# Kafka input
# ---------------------------------------------------------------------------


def _check_kafka_input(root: Path, main_go: str, failures: list[str]) -> None:
    sources = _go_sources(root, KAFKA_PKG)
    if not sources.strip():
        failures.append(
            f"no Go sources under {KAFKA_PKG}. An estate that already has every log it cares about on a broker "
            f"has to run a forwarder to re-publish them over HTTP - a second pipeline to feed the first."
        )
        return
    code = _strip_go_comments(sources)

    # One table, not two. A second copy of the classifier is how two
    # readers come to disagree about what an error means.
    if not (root / STREAMHEALTH_PKG).is_dir():
        failures.append(
            f"{STREAMHEALTH_PKG} is missing; the consumer-health table has nowhere shared to live and each "
            f"consumer will carry its own copy."
        )
    if "streamhealth." not in code:
        failures.append(
            f"{KAFKA_PKG} does not use the shared streamhealth classifier. A second copy of the permanent/"
            f"transient table is how two consumers come to disagree about what an error means."
        )
    for klass in FAILURE_CLASSES:
        if klass not in code:
            failures.append(
                f"{KAFKA_PKG} never references {klass}. Three classes, not two: without the poison class one "
                f"undecodable record backs off a subscription that is demonstrably working, and without the "
                f"permanent class a misconfiguration is retried forever as churn."
            )

    # The silent-logger trap. With a GroupID set, the consumer group's
    # dial, join and rebalance failures go only to ErrorLogger while the
    # fetch stays blocked.
    if "ErrorLogger" not in code:
        failures.append(
            f"{KAFKA_PKG} does not set ErrorLogger on the reader. kafka-go falls back to a silent logger, and "
            f"with a GroupID set that is where every dial, join and rebalance failure goes while the fetch "
            f"stays blocked - so the likeliest permanent fault is discarded inside the library."
        )

    # kafka.TCP is variadic: a comma-joined list reaches it as one hostname
    # and panics rather than failing to dial.
    if not re.search(r"strings\.Split\([^\n]*,\s*\",\"\s*\)", code):
        failures.append(
            f"{KAFKA_PKG} does not split the broker list on commas. kafka.TCP is variadic, so a comma-joined "
            f"string arrives as one hostname and panics rather than failing to dial."
        )

    # Tenant from the credential, not from the record.
    for forbidden in ("msg.Headers", "msg.Key", "msg.Value", "payload"):
        pattern = rf"[Tt]enant\w*\s*:?=\s*[^\n]*{re.escape(forbidden)}"
        if re.search(pattern, code):
            failures.append(
                f"{KAFKA_PKG} derives the tenant from {forbidden}, which the producer controls. A Kafka record "
                f"carries no authenticated principal, so that is a cross-tenant write."
            )
    if "tok.TenantID" not in code:
        failures.append(
            f"{KAFKA_PKG} does not read the tenant from the resolved token, so there is nothing in the record "
            f"a producer does not control to attribute it by."
        )

    # Wired: parsed, constructed and started.
    if "kafkainput.ParseSources(" not in main_go:
        failures.append(f"{MAIN_GO} never parses the configured sources, so none can be constructed.")
    if "kafkainput.NewSource(" not in main_go:
        failures.append(
            f"{MAIN_GO} never calls kafkainput.NewSource. A consumer nothing constructs is indistinguishable "
            f"from a feature until someone traces the call graph."
        )
    if not re.search(r"\bsrc\.Start\(", main_go):
        failures.append(f"{MAIN_GO} constructs the sources but never starts them, so no topic is ever read.")
    if not re.search(r'RegisterSubscription\(\s*"kafka_input:"', main_go):
        failures.append(
            f"{MAIN_GO} does not name each Kafka source in /readyz. A consumer detached from its topic behind "
            f"a 200 that never mentions it is indistinguishable from an idle one."
        )


# ---------------------------------------------------------------------------
# TAXII
# ---------------------------------------------------------------------------


def _check_taxii(root: Path, failures: list[str]) -> None:
    service = _read(root, TAXII_SERVICE)
    endpoint = _read(root, TAXII_ENDPOINT)
    if not service.strip() or not endpoint.strip():
        failures.append(
            "there is no TAXII 2.1 server "
            f"({TAXII_SERVICE} or {TAXII_ENDPOINT} is missing). The only TAXII-shaped route in the tree is a "
            f"demo-gated sample list, which no client can poll."
        )
        return

    endpoint_code = _strip_py_comments_and_docstrings(endpoint)
    service_code = _strip_py_comments_and_docstrings(service)

    for route in TAXII_ROUTES:
        if f'"{route}"' not in endpoint_code:
            failures.append(
                f'{TAXII_ENDPOINT} does not serve "{route}". A stock TAXII client walks discovery, API root, '
                f"collections, objects and manifest in order, and stops at the first one that 404s."
            )

    if "application/taxii+json;version=2.1" not in service_code:
        failures.append(
            f"{TAXII_SERVICE} does not define the TAXII media type. A plain application/json response is a "
            f"conformance failure some clients refuse outright."
        )

    # The pagination contract. A bare timestamp comparison skips every row
    # sharing one, and one feed poll writes many.
    if "ThreatIntelIOC.id > row_id" not in endpoint_code:
        failures.append(
            f"{TAXII_ENDPOINT} pages on the timestamp alone. Indicators written by one feed poll share "
            f"updated_at to the microsecond, so a cursor that does not break the tie on the row id either "
            f"repeats them forever or silently loses them."
        )
    if "added_after" not in endpoint_code:
        failures.append(
            f"{TAXII_ENDPOINT} does not honour added_after, which is the whole of how a TAXII client polls "
            f"incrementally - without it every poll re-downloads the collection."
        )

    # The tenant is the authenticated principal, not a path segment.
    if "current_user.tenant_id" not in endpoint_code:
        failures.append(
            f"{TAXII_ENDPOINT} does not scope by the authenticated principal's tenant. A collection id is the "
            f"one value a third party is expected to hold."
        )
    if re.search(r"tenant_id\s*=\s*(uuid\.UUID\()?api_root", endpoint_code):
        failures.append(
            f"{TAXII_ENDPOINT} derives the tenant from the API root, which is a path segment any caller can "
            f"retype - and this endpoint exists to be pointed at by a third party."
        )

    # Writes stay off. A reach-out capability ships off.
    if not re.search(r"can_write\"?\s*:\s*False", endpoint_code):
        failures.append(
            f"{TAXII_ENDPOINT} does not pin can_write to False. An inbound TAXII write is an outside party "
            f"inserting indicators that drive this tenant's detections."
        )

    if not (root / TAXII_MIGRATION).is_file():
        failures.append(f"{TAXII_MIGRATION} is missing, so taxii_collections exists in the ORM and in no database.")
    else:
        migration = _read(root, TAXII_MIGRATION)
        if "ENABLE ROW LEVEL SECURITY" not in migration:
            failures.append(
                f"{TAXII_MIGRATION} creates taxii_collections with no row-level security, so the query-layer "
                f"predicate is the only control on a table a third party addresses by id."
            )
        if "idx_ioc_taxii_paging" not in migration:
            failures.append(
                f"{TAXII_MIGRATION} does not index the paging key. Neither existing IOC index orders by the "
                f"column a TAXII client pages on, so every poll sorts the tenant's whole store."
            )

    router = _read(root, API_ROUTER)
    if "taxii.router" not in router:
        failures.append(f"{API_ROUTER} does not include the TAXII router, so the server is written and serves nothing.")


def evaluate(root: Path) -> list[str]:
    failures: list[str] = []
    main_go = _strip_go_comments(_read(root, MAIN_GO))
    if not main_go:
        failures.append(f"{MAIN_GO} is not readable, so nothing can be said about whether these inputs run.")
        return failures
    _check_otlp(root, main_go, failures)
    _check_kafka_input(root, main_go, failures)
    _check_taxii(root, failures)
    return failures


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

#: One injected violation per rule family. Each must be caught; a gate that
#: has never been shown to fail is a gate nobody can trust to pass.
_INJECTIONS = (
    ("OTLP_GONE", "a missing OTLP package"),
    ("OTLP_UNROUTED", "an OTLP receiver that is not routed"),
    ("OTLP_UNWIRED", "an OTLP receiver nothing constructs"),
    ("OTLP_NO_READYZ", "an OTLP receiver /readyz does not name"),
    ("OTLP_TEMPLATE", "a missing OTLP template"),
    ("OTLP_JSON", "an OTLP receiver that reads only protobuf"),
    ("OTLP_BLANKET_200", "an OTLP receiver with no partial-success contract"),
    ("KAFKA_GONE", "a missing Kafka input"),
    ("KAFKA_OWN_TABLE", "a Kafka input with its own failure table"),
    ("KAFKA_SILENT_LOGGER", "a Kafka reader with no ErrorLogger"),
    ("KAFKA_UNSPLIT_BROKERS", "a comma-joined broker list handed to kafka.TCP"),
    ("KAFKA_UNSTARTED", "a Kafka source that is constructed and never started"),
    ("KAFKA_TENANT_FROM_RECORD", "a tenant taken from a Kafka header"),
    ("TAXII_GONE", "a missing TAXII server"),
    ("TAXII_NO_MANIFEST", "a TAXII server with no manifest route"),
    ("TAXII_TIMESTAMP_CURSOR", "a TAXII cursor that compares only the timestamp"),
    ("TAXII_NO_RLS", "taxii_collections created without row-level security"),
    ("TAXII_UNROUTED", "a TAXII server the router does not include"),
    ("TAXII_WRITES_ON", "a TAXII server advertising can_write"),
)


def _inject(tmp: Path, kind: str) -> None:
    main_go = tmp / MAIN_GO
    kafka = tmp / KAFKA_PKG / "kafkainput.go"
    otlp = tmp / OTLP_PKG / "receiver.go"
    endpoint = tmp / TAXII_ENDPOINT

    if kind == "OTLP_GONE":
        shutil.rmtree(tmp / OTLP_PKG, ignore_errors=True)
    elif kind == "OTLP_UNROUTED":
        server = tmp / SERVER_GO
        server.write_text(server.read_text(encoding="utf-8").replace('r.Post("/logs"', 'r.Post("/otlp-logs"', 1), encoding="utf-8")
    elif kind == "OTLP_UNWIRED":
        main_go.write_text(main_go.read_text(encoding="utf-8").replace("otlp.New(", "otlpDisabled(", 1), encoding="utf-8")
    elif kind == "OTLP_NO_READYZ":
        main_go.write_text(
            main_go.read_text(encoding="utf-8").replace('RegisterSubscription("otlp_logs"', 'RegisterSubscription("otlp_unnamed"', 1),
            encoding="utf-8",
        )
    elif kind == "OTLP_TEMPLATE":
        (tmp / TEMPLATE_DIR / f"{OTLP_TEMPLATE}.yaml").unlink(missing_ok=True)
    elif kind == "OTLP_JSON":
        # Only the `case` arm is removed, leaving the error messages that
        # still name JSON. That is the realistic shape of this regression
        # and it is what the first cut of the rule missed.
        otlp.write_text(
            otlp.read_text(encoding="utf-8").replace('\tcase "application/json":\n', "", 1),
            encoding="utf-8",
        )
    elif kind == "OTLP_BLANKET_200":
        otlp.write_text(otlp.read_text(encoding="utf-8").replace("PartialSuccess", "Unused"), encoding="utf-8")
    elif kind == "KAFKA_GONE":
        shutil.rmtree(tmp / KAFKA_PKG, ignore_errors=True)
    elif kind == "KAFKA_OWN_TABLE":
        kafka.write_text(kafka.read_text(encoding="utf-8").replace("streamhealth.", "localhealth."), encoding="utf-8")
    elif kind == "KAFKA_SILENT_LOGGER":
        kafka.write_text(kafka.read_text(encoding="utf-8").replace("ErrorLogger", "unusedLogger"), encoding="utf-8")
    elif kind == "KAFKA_UNSPLIT_BROKERS":
        kafka.write_text(kafka.read_text(encoding="utf-8").replace('strings.Split(s, ",")', "[]string{s}"), encoding="utf-8")
    elif kind == "KAFKA_UNSTARTED":
        main_go.write_text(main_go.read_text(encoding="utf-8").replace("src.Start(ctx)", "_ = src"), encoding="utf-8")
    elif kind == "KAFKA_TENANT_FROM_RECORD":
        kafka.write_text(
            kafka.read_text(encoding="utf-8").replace(
                "\ttenantID := tok.TenantID.String()",
                "\ttenantID := string(msg.Headers[0].Value)",
                1,
            ),
            encoding="utf-8",
        )
    elif kind == "TAXII_GONE":
        (tmp / TAXII_SERVICE).unlink(missing_ok=True)
    elif kind == "TAXII_NO_MANIFEST":
        endpoint.write_text(
            endpoint.read_text(encoding="utf-8").replace(
                '"/{api_root}/collections/{collection_ref}/manifest/"', '"/manifest-disabled/"', 1
            ),
            encoding="utf-8",
        )
    elif kind == "TAXII_TIMESTAMP_CURSOR":
        endpoint.write_text(endpoint.read_text(encoding="utf-8").replace("ThreatIntelIOC.id > row_id", "True"), encoding="utf-8")
    elif kind == "TAXII_NO_RLS":
        migration = tmp / TAXII_MIGRATION
        migration.write_text(migration.read_text(encoding="utf-8").replace("ENABLE ROW LEVEL SECURITY", "-- relaxed"), encoding="utf-8")
    elif kind == "TAXII_UNROUTED":
        router = tmp / API_ROUTER
        router.write_text(router.read_text(encoding="utf-8").replace("taxii.router", "taxii.admin_router"), encoding="utf-8")
    elif kind == "TAXII_WRITES_ON":
        endpoint.write_text(endpoint.read_text(encoding="utf-8").replace('"can_write": False,', '"can_write": True,'), encoding="utf-8")
    else:  # pragma: no cover - a typo in the table above
        raise AssertionError(f"unknown injection {kind}")


def _self_test() -> int:
    print(f"{Path(__file__).name} self-test\n")
    results: list[tuple[str, bool]] = []

    clean = evaluate(REPO_ROOT)
    results.append(("reports the real tree clean", not clean))
    if clean:
        for line in clean:
            print(f"        unexpected: {line}")

    for kind, label in _INJECTIONS:
        tmp = Path(tempfile.mkdtemp(prefix="standard-inputs-"))
        try:
            for rel in (MAIN_GO, SERVER_GO, TAXII_SERVICE, TAXII_ENDPOINT, TAXII_MIGRATION, API_ROUTER):
                (tmp / rel).parent.mkdir(parents=True, exist_ok=True)
                source = REPO_ROOT / rel
                if source.is_file():
                    shutil.copy2(source, tmp / rel)
            for pkg in (OTLP_PKG, KAFKA_PKG, STREAMHEALTH_PKG, TEMPLATE_DIR):
                if (REPO_ROOT / pkg).is_dir():
                    shutil.copytree(REPO_ROOT / pkg, tmp / pkg)
            (tmp / INBOX_ENDPOINT).parent.mkdir(parents=True, exist_ok=True)
            if (REPO_ROOT / INBOX_ENDPOINT).is_file():
                shutil.copy2(REPO_ROOT / INBOX_ENDPOINT, tmp / INBOX_ENDPOINT)

            _inject(tmp, kind)
            results.append((f"catches {label}", bool(evaluate(tmp))))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    details: list[str] = []
    for shape in TREE_SHAPES:
        refused, detail = refuses_an_empty_tree(Path(__file__).name, shape=shape)
        results.append((f"refuses a {shape} tree rather than reporting it clean", refused))
        details.append(f"{shape}: {detail}")

    ok = True
    for description, passed in results:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    for line in "\n".join(details).splitlines():
        print(f"        {line}")
    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="inject one violation per rule and require each to be caught")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    if not (REPO_ROOT / MAIN_GO).is_file():
        print(f"check_standard_inputs: {MAIN_GO} is not there — nothing to render a verdict about.", file=sys.stderr)
        return 2

    failures = evaluate(REPO_ROOT)
    if failures:
        print("The standard inputs (depth plan 4.2 / parity 6.10) are incomplete:\n", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        print(f"\n{len(failures)} problem(s).", file=sys.stderr)
        return 1

    print(
        f"OK — the OTLP receiver reads both encodings and is routed, constructed and named by /readyz; "
        f"the Kafka input shares the streamhealth failure table and distinguishes all "
        f"{len(FAILURE_CLASSES)} classes; the TAXII server serves all {len(TAXII_ROUTES)} routes a client "
        f"walks, pages on a total order, and refuses writes. All three take the tenant from a credential."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
