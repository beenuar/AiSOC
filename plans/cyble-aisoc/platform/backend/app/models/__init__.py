"""SQLModel tables for Cyble AiSOC."""
from app.models.alert import Alert  # noqa: F401
from app.models.case import Case, CaseStatus, Severity, Verdict  # noqa: F401
from app.models.trace import AgentTrace, AgentName, TraceStep  # noqa: F401
from app.models.tool_call import ToolCall, RiskClass  # noqa: F401
from app.models.ioc import IOC, IOCType  # noqa: F401
from app.models.memory import EpisodicMemory  # noqa: F401
from app.models.graph import GraphNode, GraphEdge, NodeType, EdgeType  # noqa: F401
from app.models.hitl import HitlRequest, HitlState, HitlChannel  # noqa: F401
from app.models.tool_output_audit import ToolOutputAudit  # noqa: F401
from app.models.tenant_connector import TenantConnector  # noqa: F401
from app.models.asset import (  # noqa: F401
    Asset,
    AssetType,
    AssetCriticality,
    AssetEnvironment,
)
from app.models.workspace import (  # noqa: F401
    CaseWorkspace,
    WorkspaceOp,
    WorkspaceOpKind,
    WorkspaceAuthorKind,
)
from app.models.mssp import (  # noqa: F401
    MsspPartner,
    MsspProgramTier,
    MsspTenantLink,
)
from app.models.finops import FinOpsBudget  # noqa: F401
from app.models.academy import AcademyCertificate, AcademyProgress  # noqa: F401
from app.models.region import TenantHomeRegion, TenantRegionEvent  # noqa: F401
