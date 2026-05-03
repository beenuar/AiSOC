"""AiSOCClient — async httpx-based client for the AiSOC REST API.

Usage::

    async with AiSOCClient(base_url="https://soc.example.com", token="aisoc_...") as c:
        page = await c.alerts.list(severity="critical")
        case = await c.cases.create(title="Incident", priority="high")
        run  = await c.playbooks.run("isolate-host", trigger_data={"host": "srv-42"})
"""

from __future__ import annotations

from typing import Any, Optional, Type, TypeVar

import httpx
from pydantic import TypeAdapter

from .models import (
    Alert,
    AlertFilters,
    ApiKey,
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    Case,
    CaseFilters,
    Connector,
    DetectionRule,
    Page,
    Playbook,
    PlaybookRun,
)

T = TypeVar("T")


# ─── Error ────────────────────────────────────────────────────────────────────


class AiSOCError(Exception):
    """Raised when the AiSOC API returns a non-2xx response."""

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"AiSOC API {status_code}: {detail}")


# ─── Base resource client ─────────────────────────────────────────────────────


class _ResourceClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def _get(
        self,
        path: str,
        params: Optional[dict[str, Any]] = None,
        model: Optional[Type[T]] = None,
    ) -> Any:
        r = await self._http.get(path, params=self._clean(params))
        self._raise(r)
        if model is not None:
            return TypeAdapter(model).validate_python(r.json())
        return r.json()

    async def _post(self, path: str, body: Any, model: Optional[Type[T]] = None) -> Any:
        r = await self._http.post(path, json=body)
        self._raise(r)
        if model is not None:
            return TypeAdapter(model).validate_python(r.json())
        return r.json()

    async def _patch(self, path: str, body: Any, model: Optional[Type[T]] = None) -> Any:
        r = await self._http.patch(path, json=body)
        self._raise(r)
        if model is not None:
            return TypeAdapter(model).validate_python(r.json())
        return r.json()

    async def _delete(self, path: str) -> None:
        r = await self._http.delete(path)
        self._raise(r)

    @staticmethod
    def _clean(params: Optional[dict[str, Any]]) -> dict[str, Any]:
        if params is None:
            return {}
        return {k: v for k, v in params.items() if v is not None}

    @staticmethod
    def _raise(r: httpx.Response) -> None:
        if not r.is_success:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise AiSOCError(r.status_code, detail)


# ─── Resource sub-clients ─────────────────────────────────────────────────────


class AlertsClient(_ResourceClient):
    async def list(self, filters: Optional[AlertFilters] = None, **kwargs: Any) -> Page[Alert]:
        params = filters.model_dump(exclude_none=True) if filters else self._clean(kwargs)
        return await self._get("/api/v1/alerts", params, Page[Alert])

    async def get(self, alert_id: str) -> Alert:
        return await self._get(f"/api/v1/alerts/{alert_id}", model=Alert)

    async def update(self, alert_id: str, **data: Any) -> Alert:
        return await self._patch(f"/api/v1/alerts/{alert_id}", data, Alert)


class CasesClient(_ResourceClient):
    async def list(self, filters: Optional[CaseFilters] = None, **kwargs: Any) -> Page[Case]:
        params = filters.model_dump(exclude_none=True) if filters else self._clean(kwargs)
        return await self._get("/api/v1/cases", params, Page[Case])

    async def get(self, case_id: str) -> Case:
        return await self._get(f"/api/v1/cases/{case_id}", model=Case)

    async def create(self, **data: Any) -> Case:
        return await self._post("/api/v1/cases", data, Case)

    async def update(self, case_id: str, **data: Any) -> Case:
        return await self._patch(f"/api/v1/cases/{case_id}", data, Case)

    async def delete(self, case_id: str) -> None:
        return await self._delete(f"/api/v1/cases/{case_id}")


class DetectionsClient(_ResourceClient):
    async def list(self, page: int = 1, page_size: int = 20) -> Page[DetectionRule]:
        return await self._get("/api/v1/detections", {"page": page, "page_size": page_size}, Page[DetectionRule])

    async def get(self, rule_id: str) -> DetectionRule:
        return await self._get(f"/api/v1/detections/{rule_id}", model=DetectionRule)


class ConnectorsClient(_ResourceClient):
    async def list(self, page: int = 1, page_size: int = 20) -> Page[Connector]:
        return await self._get("/api/v1/connectors", {"page": page, "page_size": page_size}, Page[Connector])

    async def get(self, connector_id: str) -> Connector:
        return await self._get(f"/api/v1/connectors/{connector_id}", model=Connector)


class PlaybooksClient(_ResourceClient):
    async def list(self, page: int = 1, page_size: int = 20) -> Page[Playbook]:
        return await self._get("/api/v1/playbooks", {"page": page, "page_size": page_size}, Page[Playbook])

    async def get(self, playbook_id: str) -> Playbook:
        return await self._get(f"/api/v1/playbooks/{playbook_id}", model=Playbook)

    async def create(self, **data: Any) -> Playbook:
        return await self._post("/api/v1/playbooks", data, Playbook)

    async def update(self, playbook_id: str, **data: Any) -> Playbook:
        return await self._patch(f"/api/v1/playbooks/{playbook_id}", data, Playbook)

    async def delete(self, playbook_id: str) -> None:
        return await self._delete(f"/api/v1/playbooks/{playbook_id}")

    async def run(
        self,
        playbook_id: str,
        trigger_data: Optional[dict[str, Any]] = None,
    ) -> PlaybookRun:
        return await self._post(
            f"/api/v1/playbooks/{playbook_id}/run",
            {"trigger_data": trigger_data or {}},
            PlaybookRun,
        )

    async def get_run(self, run_id: str) -> PlaybookRun:
        return await self._get(f"/api/v1/playbooks/runs/{run_id}", model=PlaybookRun)


class ApiKeysClient(_ResourceClient):
    async def list(self) -> Page[ApiKey]:
        return await self._get("/api/v1/api-keys", model=Page[ApiKey])

    async def create(self, req: ApiKeyCreateRequest) -> ApiKeyCreateResponse:
        return await self._post(
            "/api/v1/api-keys",
            req.model_dump(exclude_none=True),
            ApiKeyCreateResponse,
        )

    async def revoke(self, key_id: str) -> None:
        return await self._delete(f"/api/v1/api-keys/{key_id}")


# ─── Main client ─────────────────────────────────────────────────────────────


class AiSOCClient:
    """Async Python client for the AiSOC REST API.

    Must be used as an async context manager::

        async with AiSOCClient(base_url="...", token="...") as client:
            alerts = await client.alerts.list()

    Or manage the lifecycle manually::

        client = AiSOCClient(base_url="...", token="...")
        await client.__aenter__()
        try:
            ...
        finally:
            await client.__aexit__(None, None, None)
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 30.0,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._extra_headers = headers or {}
        self._http: Optional[httpx.AsyncClient] = None

        # Placeholders — initialised in __aenter__
        self.alerts: AlertsClient
        self.cases: CasesClient
        self.detections: DetectionsClient
        self.connectors: ConnectorsClient
        self.playbooks: PlaybooksClient
        self.api_keys: ApiKeysClient

    async def __aenter__(self) -> "AiSOCClient":
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
                **self._extra_headers,
            },
            timeout=self._timeout,
        )
        self.alerts = AlertsClient(self._http)
        self.cases = CasesClient(self._http)
        self.detections = DetectionsClient(self._http)
        self.connectors = ConnectorsClient(self._http)
        self.playbooks = PlaybooksClient(self._http)
        self.api_keys = ApiKeysClient(self._http)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def graphql(
        self,
        query: str,
        variables: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL query against the /graphql endpoint."""
        if self._http is None:
            raise RuntimeError("Use AiSOCClient as an async context manager")
        r = await self._http.post("/graphql", json={"query": query, "variables": variables})
        if not r.is_success:
            raise AiSOCError(r.status_code, r.text)
        return r.json()  # type: ignore[return-value]
