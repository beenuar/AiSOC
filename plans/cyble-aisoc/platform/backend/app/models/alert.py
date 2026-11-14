"""SIEM/EDR alert. OCSF-aligned subset."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column


class Alert(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    external_id: str = Field(index=True)
    tenant_id: str = Field(default="demo-tenant", index=True)
    source: str  # e.g., "splunk", "sentinelone", "okta"
    title: str
    description: str = ""
    severity: str = "medium"  # critical | high | medium | low | info
    detection_rule: str | None = None
    mitre_tactics: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    mitre_techniques: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    src_user: str | None = None
    src_host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process_name: str | None = None
    file_hash: str | None = None
    raw: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    case_id: int | None = Field(default=None, foreign_key="case.id", index=True)
