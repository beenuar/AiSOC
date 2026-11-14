"""Realtime co-investigation workspace (Theme 2l).

Public surface for the workspace subsystem. Importers should pull
``service`` for write-path operations (``apply_op``, ``ensure_workspace``),
``mentions`` for the @agent parser, and ``dispatcher`` for fanning a
persisted ``mention`` op out to the named agents.
"""
from app.workspace.dispatcher import (  # noqa: F401
    DISPATCHABLE_AGENTS,
    dispatch_mentions,
)
from app.workspace.mentions import (  # noqa: F401
    Mention,
    parse_mentions,
    unique_agents,
)
from app.workspace.service import (  # noqa: F401
    AGENT_NAMES,
    SUPPORTED_OP_KINDS,
    WorkspaceError,
    apply_op,
    ensure_workspace,
    fetch_ops,
    get_workspace,
    serialize_op,
)
