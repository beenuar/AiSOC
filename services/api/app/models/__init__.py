"""ORM models package - imports all models for Alembic and SQLAlchemy."""

from app.db.database import Base
from app.models.alert import Alert
from app.models.asset import AlertAssetCorrelation, Asset, AssetVulnerability
from app.models.case import Case, CaseTask, CaseTimeline
from app.models.connector import Connector
from app.models.detection_proposal import DetectionEvalBaseline, DetectionRuleProposal
from app.models.detection_rule import DetectionRule
from app.models.easm import ExternalAsset, ExternalAssetDrift
from app.models.identity_graph import AlertIdentityLink, IdentityEdge, IdentityNode
from app.models.inbox import TenantInboxToken
from app.models.insider_threat import InsiderIndicator, InsiderPeerGroup, UserRiskProfile
from app.models.institutional_memory import InstitutionalMemory
from app.models.investigation import (
    InvestigationArtifact,
    InvestigationEvent,
    InvestigationRun,
)
from app.models.llm_credential import TenantLlmCredential
from app.models.mssp import (
    MSSPDelegation,
    MSSPRuleOverride,
    MSSPRulePack,
    MSSPRulePackAssignment,
    MSSPRulePackRule,
    MSSPTenantMetrics,
    MSSPTenantNote,
)
from app.models.oauth import OAuthAppCredential, OAuthState
from app.models.posture import PostureDriftEvent, PostureFinding, PostureScanRun
from app.models.remediation import RemediationGateLog, RemediationMaturity, RemediationWhitelist
from app.models.report import ReportArtefact, ReportTemplate
from app.models.responder import (
    AgentApproval,
    OnCallStatus,
    PasskeyChallenge,
    PasskeyCredential,
)
from app.models.saved_view import SavedView
from app.models.tenant import ApiKey, Tenant, User
from app.models.threat_intel import ThreatActor, ThreatIntelFeed, ThreatIntelIOC

__all__ = [
    "Base",
    "Tenant",
    "User",
    "ApiKey",
    "Alert",
    "AlertAssetCorrelation",
    "AlertIdentityLink",
    "Asset",
    "AssetVulnerability",
    "Case",
    "CaseTask",
    "CaseTimeline",
    "Connector",
    "DetectionRule",
    "DetectionRuleProposal",
    "DetectionEvalBaseline",
    "IdentityEdge",
    "IdentityNode",
    "InsiderIndicator",
    "InsiderPeerGroup",
    "InstitutionalMemory",
    "InvestigationRun",
    "InvestigationEvent",
    "InvestigationArtifact",
    "MSSPDelegation",
    "MSSPRuleOverride",
    "MSSPRulePack",
    "MSSPRulePackAssignment",
    "MSSPRulePackRule",
    "MSSPTenantMetrics",
    "MSSPTenantNote",
    "OAuthAppCredential",
    "OAuthState",
    "TenantInboxToken",
    "TenantLlmCredential",
    "PasskeyCredential",
    "PasskeyChallenge",
    "OnCallStatus",
    "AgentApproval",
    "PostureDriftEvent",
    "PostureFinding",
    "PostureScanRun",
    "RemediationGateLog",
    "RemediationMaturity",
    "RemediationWhitelist",
    "ReportArtefact",
    "ReportTemplate",
    "SavedView",
    "ThreatActor",
    "ThreatIntelFeed",
    "ThreatIntelIOC",
    "UserRiskProfile",
    "ExternalAsset",
    "ExternalAssetDrift",
]
