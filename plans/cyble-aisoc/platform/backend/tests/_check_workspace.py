"""End-to-end smoke test for the realtime co-investigation workspace (Theme 2l).

Verifies that the workspace subsystem behaves as the wire contract requires:

1. **Mention parser** (`parse_mentions` / `unique_agents`)
   - Resolves canonical agent names and short-form aliases.
   - Ignores unknown handles.
   - Strips mentions inside fenced code blocks and inline code spans.
   - Deduplicates repeated mentions while preserving first-seen order.

2. **Service write path** (`ensure_workspace`, `apply_op`)
   - Creates the parent `CaseWorkspace` lazily on first write.
   - Allocates `seq` monotonically per-workspace (1, 2, 3, …).
   - Rejects unknown op kinds and bad author kinds with `WorkspaceError`.
   - Refuses cross-tenant access (case exists but caller is on a different
     tenant → treated as not-found to avoid leaking existence).

3. **Service read path** (`fetch_ops`, `serialize_op`)
   - Returns ops in ascending `seq` order.
   - Honors `since_seq` filtering and the `limit` cap.
   - Serialized envelope has the expected wire shape (id/seq/kind/payload/
     author_*/client_op_id/created_at).

4. **Dispatcher** (`dispatch_mentions`)
   - Emits exactly one `agent.started` op per mentioned agent (synchronous,
     before the agent runs).
   - Eventually emits one `agent.finished` op per mention with `ok=False`
     and a summary that names the missing agent when the agent class is
     not registered in `DISPATCHABLE_AGENTS`.

The test runs against an isolated SQLite file under a tempdir so it
does not collide with the dev DB.

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_workspace.py

Exits non-zero on any failed check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-workspace-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.db import engine, init_db  # noqa: E402
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.trace import AgentName  # noqa: E402
from app.models.workspace import (  # noqa: E402
    CaseWorkspace,
    WorkspaceAuthorKind,
    WorkspaceOp,
    WorkspaceOpKind,
)
from app.workspace import (  # noqa: E402
    AGENT_NAMES,
    SUPPORTED_OP_KINDS,
    WorkspaceError,
    apply_op,
    dispatch_mentions,
    ensure_workspace,
    fetch_ops,
    get_workspace,
    parse_mentions,
    serialize_op,
    unique_agents,
)
from app.workspace import dispatcher as _dispatcher_mod  # noqa: E402


# ── tiny harness ────────────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(title: str) -> None:
    print(f"\n── {title} ──")


# ── fixture builders ────────────────────────────────────────────────────


TENANT_A = "t-alpha"
TENANT_B = "t-bravo"


def _seed_case(tenant_id: str, title: str = "Workspace test case") -> int:
    """Insert a minimal Case row for the given tenant and return its id."""
    with Session(engine) as s:
        c = Case(
            title=title,
            severity=Severity.MEDIUM,
            status=CaseStatus.INVESTIGATING,
            tenant_id=tenant_id,
        )
        s.add(c)
        s.commit()
        s.refresh(c)
        assert c.id is not None
        return c.id


# ── 1. mention parser ───────────────────────────────────────────────────


def test_mention_parser() -> None:
    section("mention parser")

    # 1a. exact canonical handles
    mentions = parse_mentions("@investigator look at host bravo-12")
    check(
        "canonical @investigator resolves",
        len(mentions) == 1 and mentions[0].agent is AgentName.INVESTIGATOR,
        detail=f"got {[m.agent for m in mentions]}",
    )
    check(
        "canonical mention preserves raw text",
        mentions and mentions[0].raw == "@investigator",
        detail=f"raw={mentions[0].raw if mentions else None!r}",
    )

    # 1b. short-form aliases
    cases = [
        ("@phish header looks spoofed", AgentName.PHISHING_TRIAGE),
        ("@phishing please triage", AgentName.PHISHING_TRIAGE),
        ("@saas posture check", AgentName.SAAS_POSTURE),
        ("@sspm baseline drift", AgentName.SAAS_POSTURE),
        ("@detect write a sigma", AgentName.DETECTION_AUTHOR),
        ("@detection author one", AgentName.DETECTION_AUTHOR),
        ("@report close this", AgentName.REPORTER),
        ("@respond please isolate", AgentName.RESPONDER),
        ("@triage initial pass", AgentName.TRIAGER),
    ]
    for text, expected in cases:
        ms = parse_mentions(text)
        check(
            f"alias resolves: {text.split()[0]!r} → {expected.value}",
            len(ms) == 1 and ms[0].agent is expected,
            detail=f"got {[m.agent for m in ms]}",
        )

    # 1c. unknown handles silently ignored
    ms = parse_mentions("@charlie can you take this? @nope not really")
    check("unknown handles ignored", ms == [], detail=f"got {ms!r}")

    # 1d. mention inside fenced code block is skipped
    fenced = (
        "Investigator note:\n"
        "```bash\n"
        "grep '@investigator' /var/log/case.log\n"
        "```\n"
        "@responder please proceed"
    )
    ms = parse_mentions(fenced)
    check(
        "code fence strips @investigator inside ``` block",
        len(ms) == 1 and ms[0].agent is AgentName.RESPONDER,
        detail=f"got {[m.agent for m in ms]}",
    )

    # 1e. mention inside inline code span is skipped
    inline = "see `@investigator` log line, then @responder"
    ms = parse_mentions(inline)
    check(
        "inline code span strips @investigator",
        len(ms) == 1 and ms[0].agent is AgentName.RESPONDER,
        detail=f"got {[m.agent for m in ms]}",
    )

    # 1f. dedup via unique_agents preserves first-seen order
    text = "@investigator pls. cc @responder and again @investigator"
    ms = parse_mentions(text)
    agents = unique_agents(ms)
    check(
        "unique_agents dedups and preserves first-seen order",
        agents == [AgentName.INVESTIGATOR, AgentName.RESPONDER],
        detail=f"got {agents!r}",
    )

    # 1g. empty / None inputs are safe
    check("parse_mentions('') == []", parse_mentions("") == [])

    # 1h. AGENT_NAMES is the closed set the parser advertises
    check(
        "AGENT_NAMES non-empty",
        len(AGENT_NAMES) > 0,
        detail=f"got {len(AGENT_NAMES)} names",
    )


# ── 2. service write path ───────────────────────────────────────────────


def test_service_write_path() -> None:
    section("service: ensure_workspace + apply_op")

    case_id = _seed_case(TENANT_A, title="alpha case")

    # 2a. ensure_workspace creates the parent row on first call
    with Session(engine) as s:
        ws = ensure_workspace(s, case_id=case_id, tenant_id=TENANT_A)
        check(
            "ensure_workspace creates parent on first access",
            ws is not None and ws.case_id == case_id and ws.head_seq == 0,
            detail=f"ws={ws!r}",
        )

    # 2b. second call returns the same workspace (idempotent)
    with Session(engine) as s:
        ws2 = ensure_workspace(s, case_id=case_id, tenant_id=TENANT_A)
        check(
            "ensure_workspace is idempotent (same id on second call)",
            ws2.id == ws.id,
            detail=f"first={ws.id} second={ws2.id}",
        )

    # 2c. cross-tenant access is rejected as not-found
    with Session(engine) as s:
        try:
            ensure_workspace(s, case_id=case_id, tenant_id=TENANT_B)
            cross_tenant_blocked = False
        except WorkspaceError:
            cross_tenant_blocked = True
        check(
            "cross-tenant ensure_workspace raises WorkspaceError",
            cross_tenant_blocked,
        )

    # 2d. apply_op allocates monotonic seq starting at 1
    seqs: list[int] = []
    with Session(engine) as s:
        for i in range(3):
            op = apply_op(
                s,
                case_id=case_id,
                tenant_id=TENANT_A,
                kind=WorkspaceOpKind.NOTE_APPEND.value,
                payload={"text": f"note {i}", "block_id": f"blk-{i}"},
                author_kind=WorkspaceAuthorKind.HUMAN.value,
                author_id="analyst-1",
                broadcast=False,
            )
            seqs.append(op.seq)

    check(
        "apply_op allocates seq monotonically per-workspace",
        seqs == [1, 2, 3],
        detail=f"got {seqs}",
    )

    # 2e. head_seq is rolled forward on the parent workspace
    with Session(engine) as s:
        ws_after = get_workspace(s, case_id=case_id, tenant_id=TENANT_A)
        check(
            "workspace head_seq tracks latest op seq",
            ws_after is not None and ws_after.head_seq == 3,
            detail=f"head_seq={ws_after.head_seq if ws_after else None}",
        )

    # 2f. unknown op kind rejected
    with Session(engine) as s:
        try:
            apply_op(
                s,
                case_id=case_id,
                tenant_id=TENANT_A,
                kind="something.invented",
                broadcast=False,
            )
            unknown_kind_blocked = False
        except WorkspaceError:
            unknown_kind_blocked = True
        check(
            "apply_op rejects unknown op kind",
            unknown_kind_blocked,
        )

    # 2g. unknown author_kind rejected
    with Session(engine) as s:
        try:
            apply_op(
                s,
                case_id=case_id,
                tenant_id=TENANT_A,
                kind=WorkspaceOpKind.NOTE_APPEND.value,
                payload={"text": "x"},
                author_kind="alien",
                broadcast=False,
            )
            bad_author_blocked = False
        except WorkspaceError:
            bad_author_blocked = True
        check(
            "apply_op rejects unknown author_kind",
            bad_author_blocked,
        )

    # 2h. SUPPORTED_OP_KINDS exposes the full enum
    check(
        "SUPPORTED_OP_KINDS matches WorkspaceOpKind",
        SUPPORTED_OP_KINDS == frozenset(k.value for k in WorkspaceOpKind),
    )


# ── 3. service read path ────────────────────────────────────────────────


def test_service_read_path() -> None:
    section("service: fetch_ops + serialize_op + tenant isolation")

    # Two cases in two tenants, each with three ops.
    case_a = _seed_case(TENANT_A, title="alpha case 2")
    case_b = _seed_case(TENANT_B, title="bravo case")

    with Session(engine) as s:
        for tenant, cid, n in [(TENANT_A, case_a, 3), (TENANT_B, case_b, 3)]:
            for i in range(n):
                apply_op(
                    s,
                    case_id=cid,
                    tenant_id=tenant,
                    kind=WorkspaceOpKind.NOTE_APPEND.value,
                    payload={"text": f"{tenant}-{i}", "block_id": f"b-{i}"},
                    author_kind=WorkspaceAuthorKind.HUMAN.value,
                    author_id=f"user@{tenant}",
                    broadcast=False,
                )

    # 3a. fetch_ops returns ascending seq, scoped to tenant
    with Session(engine) as s:
        ops_a = fetch_ops(s, case_id=case_a, tenant_id=TENANT_A)
        ops_b = fetch_ops(s, case_id=case_b, tenant_id=TENANT_B)
    check(
        "fetch_ops returns 3 ops for tenant A",
        len(ops_a) == 3,
        detail=f"got {len(ops_a)}",
    )
    check(
        "fetch_ops returns 3 ops for tenant B",
        len(ops_b) == 3,
        detail=f"got {len(ops_b)}",
    )
    check(
        "fetch_ops ascending seq for tenant A",
        [op.seq for op in ops_a] == [1, 2, 3],
        detail=f"got {[op.seq for op in ops_a]}",
    )

    # 3b. cross-tenant fetch returns nothing
    with Session(engine) as s:
        cross = fetch_ops(s, case_id=case_a, tenant_id=TENANT_B)
    check(
        "cross-tenant fetch_ops returns empty",
        cross == [],
        detail=f"got {cross!r}",
    )

    # 3c. since_seq filter is strict (>, not >=)
    with Session(engine) as s:
        ops_after_1 = fetch_ops(
            s, case_id=case_a, tenant_id=TENANT_A, since_seq=1
        )
    check(
        "since_seq=1 returns seqs > 1",
        [op.seq for op in ops_after_1] == [2, 3],
        detail=f"got {[op.seq for op in ops_after_1]}",
    )

    # 3d. limit cap respected
    with Session(engine) as s:
        capped = fetch_ops(s, case_id=case_a, tenant_id=TENANT_A, limit=1)
    check(
        "limit=1 returns exactly one op",
        len(capped) == 1 and capped[0].seq == 1,
        detail=f"got {[op.seq for op in capped]}",
    )

    # 3e. limit <= 0 short-circuits to empty
    with Session(engine) as s:
        empty = fetch_ops(s, case_id=case_a, tenant_id=TENANT_A, limit=0)
    check("limit=0 short-circuits to []", empty == [])

    # 3f. serialize_op shape
    op0 = ops_a[0]
    env = serialize_op(op0)
    expected_keys = {
        "id",
        "seq",
        "kind",
        "payload",
        "author_kind",
        "author_id",
        "client_op_id",
        "created_at",
    }
    check(
        "serialize_op envelope has exactly the wire keys",
        set(env.keys()) == expected_keys,
        detail=f"got {sorted(env.keys())}",
    )
    check(
        "serialize_op preserves payload dict",
        env["payload"] == op0.payload,
    )
    check(
        "serialize_op uses ISO created_at",
        isinstance(env["created_at"], str) and "T" in env["created_at"],
        detail=f"got {env['created_at']!r}",
    )


# ── 4. dispatcher ───────────────────────────────────────────────────────


def test_dispatcher_unknown_agent() -> None:
    """Force the dispatcher down the 'no runnable class' branch.

    We temporarily clear ``DISPATCHABLE_AGENTS`` so every mentioned agent
    falls through to the explanatory ``agent.finished`` path. This lets
    us validate the dispatcher's ack contract without instantiating
    real agent classes (which would require LLM/connector setup).
    """
    section("dispatcher: started+finished ops per mention")

    case_id = _seed_case(TENANT_A, title="dispatch case")

    # Save and clear the runtime registry so all mentions hit the
    # "no runnable implementation" branch.
    saved_registry = dict(_dispatcher_mod.DISPATCHABLE_AGENTS)
    _dispatcher_mod.DISPATCHABLE_AGENTS.clear()
    try:
        # Persist the parent mention op the dispatcher will reference.
        with Session(engine) as s:
            mention_op = apply_op(
                s,
                case_id=case_id,
                tenant_id=TENANT_A,
                kind=WorkspaceOpKind.MENTION.value,
                payload={"text": "@investigator @responder please help"},
                author_kind=WorkspaceAuthorKind.HUMAN.value,
                author_id="analyst-2",
                broadcast=False,
            )
            mention_op_id = mention_op.id
            assert mention_op_id is not None

        async def _run() -> None:
            tasks = dispatch_mentions(
                tenant_id=TENANT_A,
                case_id=case_id,
                mention_op_id=mention_op_id,
                agents=[AgentName.INVESTIGATOR, AgentName.RESPONDER],
                requested_by="analyst-2",
            )
            # Drive the background tasks to completion inside the same
            # event loop they were scheduled on. Without this, asyncio.run
            # would tear the loop down before ``agent.finished`` gets
            # written, and we'd read a partial workspace.
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            # Yield once more so any broadcast tasks (created via
            # ``loop.create_task`` inside ``apply_op``) get a chance to
            # run before the loop closes.
            await asyncio.sleep(0)

        asyncio.run(_run())

        # Read back what landed in the workspace.
        with Session(engine) as s:
            ops = fetch_ops(s, case_id=case_id, tenant_id=TENANT_A)

        kinds = [op.kind for op in ops]
        check(
            "mention op persisted",
            kinds.count(WorkspaceOpKind.MENTION.value) == 1,
            detail=f"kinds={kinds}",
        )
        check(
            "two agent.started ops (one per dispatched agent)",
            kinds.count(WorkspaceOpKind.AGENT_STARTED.value) == 2,
            detail=f"kinds={kinds}",
        )
        check(
            "two agent.finished ops (one per dispatched agent)",
            kinds.count(WorkspaceOpKind.AGENT_FINISHED.value) == 2,
            detail=f"kinds={kinds}",
        )

        # Started ops carry the right author + agent identity
        started_ops = [
            op for op in ops if op.kind == WorkspaceOpKind.AGENT_STARTED.value
        ]
        check(
            "agent.started authored by system (dispatcher)",
            all(
                op.author_kind == WorkspaceAuthorKind.SYSTEM.value
                and op.author_id == "dispatcher"
                for op in started_ops
            ),
            detail=f"got {[(op.author_kind, op.author_id) for op in started_ops]}",
        )
        started_agents = {op.payload.get("agent") for op in started_ops}
        check(
            "agent.started payload covers both dispatched agents",
            started_agents
            == {AgentName.INVESTIGATOR.value, AgentName.RESPONDER.value},
            detail=f"got {started_agents}",
        )

        # Finished ops should be marked ok=False with a human summary
        finished_ops = [
            op for op in ops if op.kind == WorkspaceOpKind.AGENT_FINISHED.value
        ]
        check(
            "agent.finished marked ok=False (no runnable class)",
            all(op.payload.get("ok") is False for op in finished_ops),
            detail=f"got {[op.payload.get('ok') for op in finished_ops]}",
        )
        check(
            "agent.finished authored by agent (for UI attribution)",
            all(
                op.author_kind == WorkspaceAuthorKind.AGENT.value
                for op in finished_ops
            ),
            detail=f"got {[op.author_kind for op in finished_ops]}",
        )
        check(
            "agent.finished references the parent mention op id",
            all(
                op.payload.get("mention_op_id") == mention_op_id
                for op in finished_ops
            ),
            detail=(
                "got "
                f"{[op.payload.get('mention_op_id') for op in finished_ops]}"
            ),
        )

        # 4z. seq is still monotonic across the whole sequence
        seqs = [op.seq for op in ops]
        check(
            "seq remains strictly monotonic after dispatch",
            seqs == sorted(set(seqs)) and len(set(seqs)) == len(seqs),
            detail=f"got {seqs}",
        )
    finally:
        _dispatcher_mod.DISPATCHABLE_AGENTS.update(saved_registry)


# ── main ────────────────────────────────────────────────────────────────


def main() -> int:
    print(f"Workspace smoke test using DB at {DB_PATH}")
    init_db()

    test_mention_parser()
    test_service_write_path()
    test_service_read_path()
    test_dispatcher_unknown_agent()

    print()
    if _FAILED:
        print(f"FAILED: {len(_FAILED)} check(s)")
        for label in _FAILED:
            print(f"  - {label}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
