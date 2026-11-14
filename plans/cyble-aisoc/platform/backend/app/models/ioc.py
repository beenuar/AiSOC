"""Indicators of Compromise from CTI feeds (Cyble-native + external)."""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA1 = "sha1"
    HASH_SHA256 = "sha256"
    EMAIL = "email"
    CIDR = "cidr"
    USER = "user"
    BTC_ADDRESS = "btc_address"


class IOC(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    # IOCs are tenant-scoped. Even when sourced from a Cyble-native global
    # feed we materialize a row per tenant so RLS/tenant-filter is uniform
    # across every read path. `tenant_id="__global__"` is reserved for the
    # shared feed and is readable by any tenant (handled in query helpers).
    tenant_id: str = Field(default="demo-tenant", index=True)
    value: str = Field(index=True)
    type: IOCType = Field(index=True)
    threat_score: int = 0  # 0..100
    confidence: float = 0.0  # 0..1
    sources: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    tags: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cyble_native: bool = False  # came from Cyble's proprietary feeds
    description: str = ""
