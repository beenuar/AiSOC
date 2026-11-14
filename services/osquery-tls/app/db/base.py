"""SQLAlchemy declarative base for the osquery-tls service."""

from __future__ import annotations

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """All ORM models inherit from this base."""
