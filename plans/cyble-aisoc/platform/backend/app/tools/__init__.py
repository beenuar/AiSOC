"""MCP-aligned tool registry. Every tool declares its risk class and integration."""
from app.tools.registry import registry, ToolDef, RiskClass  # noqa: F401
from app.tools import (  # noqa: F401
    siem,
    edr,
    cti,
    idp,
    cloud,
    saas,
    email_tool,
    phishing,
    ticketing,
    comms,
    memory,
    asset,
    forensics,
    cold_archive_tool,
)
