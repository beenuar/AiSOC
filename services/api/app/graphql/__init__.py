"""Strawberry GraphQL gateway for AiSOC.

Mounted at /graphql — provides a typed query interface over alerts, cases,
investigations, and playbooks.  The resolver layer re-uses the same
SQLAlchemy session and auth dependencies as the REST endpoints.
"""

from .schema import schema  # noqa: F401 – re-export for main.py

__all__ = ["schema"]
