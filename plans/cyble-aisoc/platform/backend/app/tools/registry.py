"""Central tool registry.

Mirrors the MCP-aligned design from the plan:
- declared schema (params + result)
- risk classification gates HITL
- integration tag for tenant-level allowlists

Per-tenant allowlists live here too: a tenant might be entitled to
Splunk + Okta but not the Cyble-native dark-web pivot tools, or an
MSSP might restrict destructive actions to a subset of customers.
The default policy is "every tool is allowed for every tenant" — call
`set_tenant_allowlist()` / `set_tenant_denylist()` at bootstrap
(or on entitlement change) to tighten it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional

from app.models.tool_call import RiskClass

ToolHandler = Callable[..., Awaitable[dict[str, Any]]]
# (original_params, original_result) -> reverse_params
# Pure function: must be deterministic and side-effect-free. Runs while the
# rollback service is building the paired reverse ToolCall, before any
# external write happens.
ReverseParamsBuilder = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]


@dataclass
class ToolDef:
    name: str
    integration: str  # "splunk", "sentinelone", "okta", "cyble-cti", ...
    risk_class: RiskClass
    description: str
    params_schema: dict[str, Any]
    handler: ToolHandler
    # JSON-schema describing the expected SHAPE of the tool's result. The
    # prompt-injection defense layer uses this to (a) reject obviously
    # tampered-with outputs and (b) drop unknown fields before the result
    # re-enters the LLM context. Empty dict = no validation.
    result_schema: dict[str, Any] = field(default_factory=dict)
    cyble_native: bool = False  # tags Cyble's proprietary moat tools
    tags: list[str] = field(default_factory=list)
    # ── Reverse-action pairing (t1-reverse-actions) ────────────────────
    # `reverse_tool` names the registered tool that undoes this one
    # (e.g. ``edr.isolate_host`` -> ``edr.release_host``). When unset the
    # action is treated as irreversible by the rollback service.
    # `reverse_params_builder` derives the reverse tool's params from this
    # tool's original params + result — it MUST be pure (the rollback
    # service runs it while building a paired ToolCall before any
    # external write).
    reverse_tool: Optional[str] = None
    reverse_params_builder: Optional[ReverseParamsBuilder] = None
    # `forward_only_reason` is the documented justification for why a
    # WRITE-* tool intentionally has no paired reverse. The rollback
    # service surfaces this string in the eligibility verdict so the
    # analyst UI can show *why* the Undo button is disabled
    # ("re-granting requires fresh user consent") instead of a generic
    # "not reversible". The structural reverse-coverage test
    # (tests/_check_reverse_coverage.py) requires every
    # WRITE_REVERSIBLE / WRITE_SIGNIFICANT tool to declare EITHER a
    # reverse_tool OR a forward_only_reason — never both, never neither.
    forward_only_reason: Optional[str] = None

    @property
    def is_reversible(self) -> bool:
        """True iff this tool has a paired reverse handler registered."""
        return self.reverse_tool is not None

    @property
    def is_forward_only(self) -> bool:
        """True iff this tool has a documented opt-out from rollback."""
        return self.forward_only_reason is not None


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDef] = {}
        # tenant_id -> allowed set; None means "no restriction"
        self._tenant_allow: dict[str, set[str] | None] = {}
        # tenant_id -> denied set (subtracted from allowed); empty default
        self._tenant_deny: dict[str, set[str]] = {}

    def register(self, td: ToolDef) -> ToolDef:
        if td.name in self._tools:
            raise ValueError(f"tool already registered: {td.name}")
        self._tools[td.name] = td
        return td

    def get(self, name: str) -> ToolDef | None:
        return self._tools.get(name)

    def all(self) -> list[ToolDef]:
        return list(self._tools.values())

    def by_integration(self, integration: str) -> list[ToolDef]:
        return [t for t in self._tools.values() if t.integration == integration]

    def by_risk(self, max_risk: RiskClass) -> list[ToolDef]:
        order = [
            RiskClass.READ,
            RiskClass.WRITE_REVERSIBLE,
            RiskClass.WRITE_SIGNIFICANT,
            RiskClass.DESTRUCTIVE,
        ]
        cutoff = order.index(max_risk)
        return [t for t in self._tools.values() if order.index(t.risk_class) <= cutoff]

    # ── Per-tenant allowlisting ─────────────────────────────────────────
    def set_tenant_allowlist(
        self, tenant_id: str, tool_names: list[str] | None
    ) -> None:
        """Restrict `tenant_id` to the given set of tool names.

        Pass `None` to clear the allowlist (= every tool allowed).
        """
        if tool_names is None:
            self._tenant_allow.pop(tenant_id, None)
            return
        self._tenant_allow[tenant_id] = set(tool_names)

    def set_tenant_denylist(
        self, tenant_id: str, tool_names: list[str]
    ) -> None:
        """Explicitly deny named tools for `tenant_id` (overrides allow)."""
        if not tool_names:
            self._tenant_deny.pop(tenant_id, None)
            return
        self._tenant_deny[tenant_id] = set(tool_names)

    def is_allowed_for_tenant(self, tool_name: str, tenant_id: str) -> bool:
        """Single-tool check used by the orchestrator before dispatching."""
        if tool_name in self._tenant_deny.get(tenant_id, set()):
            return False
        allow = self._tenant_allow.get(tenant_id)
        if allow is None:
            return True
        return tool_name in allow

    def allowed_for_tenant(self, tenant_id: str) -> list[ToolDef]:
        """Materialized view of the tools `tenant_id` can call right now."""
        return [
            t for t in self._tools.values()
            if self.is_allowed_for_tenant(t.name, tenant_id)
        ]


registry = ToolRegistry()


def tool(
    *,
    name: str,
    integration: str,
    risk: RiskClass,
    description: str,
    params: dict[str, Any] | None = None,
    result: dict[str, Any] | None = None,
    cyble_native: bool = False,
    tags: list[str] | None = None,
    reverse_tool: str | None = None,
    reverse_params_builder: ReverseParamsBuilder | None = None,
    forward_only_reason: str | None = None,
):
    """Decorator: declare an async function as a registered tool.

    `result` is an optional JSON-schema describing the expected shape of the
    handler's return value. The prompt-injection defense layer enforces it
    before tool output re-enters the LLM context.

    `reverse_tool` is the registered name of a tool that semantically undoes
    this one (e.g. ``edr.isolate_host`` -> ``edr.release_host``). The rollback
    service uses `reverse_params_builder(original_params, original_result)`
    to derive the reverse tool's params. Both arguments must be set together
    for the tool to be considered rollback-eligible.

    `forward_only_reason` is the documented opt-out: set it on a WRITE-*
    tool that *deliberately* has no paired reverse (e.g. revoking an OAuth
    grant — re-granting requires fresh user consent, not an automated
    rollback). It is surfaced verbatim in the eligibility verdict so the
    analyst UI can explain *why* Undo is disabled. The structural
    reverse-coverage test requires every WRITE_REVERSIBLE /
    WRITE_SIGNIFICANT tool to declare EITHER a reverse_tool OR a
    forward_only_reason — never both, never neither.
    """

    if (reverse_tool is None) != (reverse_params_builder is None):
        raise ValueError(
            f"tool '{name}': reverse_tool and reverse_params_builder must be "
            "declared together (or both omitted)"
        )
    if reverse_tool is not None and forward_only_reason is not None:
        raise ValueError(
            f"tool '{name}': reverse_tool and forward_only_reason are "
            "mutually exclusive — a tool either has a paired reverse or "
            "is documented as forward-only, not both"
        )
    if forward_only_reason is not None and risk not in (
        RiskClass.WRITE_REVERSIBLE,
        RiskClass.WRITE_SIGNIFICANT,
    ):
        raise ValueError(
            f"tool '{name}': forward_only_reason only makes sense on "
            "WRITE_REVERSIBLE / WRITE_SIGNIFICANT tools — READ has nothing "
            "to undo and DESTRUCTIVE is forward-only by policy"
        )

    def deco(fn: ToolHandler) -> ToolHandler:
        registry.register(
            ToolDef(
                name=name,
                integration=integration,
                risk_class=risk,
                description=description,
                params_schema=params or {},
                result_schema=result or {},
                handler=fn,
                cyble_native=cyble_native,
                tags=tags or [],
                reverse_tool=reverse_tool,
                reverse_params_builder=reverse_params_builder,
                forward_only_reason=forward_only_reason,
            )
        )
        return fn

    return deco
