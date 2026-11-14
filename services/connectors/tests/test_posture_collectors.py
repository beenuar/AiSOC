"""The posture collectors, driven through the connectors that own them.

Why these tests go through ``get_resource_config`` rather than calling the
collector functions directly
---------------------------------------------------------------------------
The gap these collectors close was not "nobody wrote a collector". It was
that the resolver subsystem had no way to *obtain* a snapshot, so every live
call answered 412 while the endpoint reported ``coverage: "full"``. A test
that calls ``posture.azure.collect`` proves a function works; it does not
prove the connector routes the sentinel to it, which is the half that was
missing. So the cloud tests go in through ``connector.get_resource_config(
POSTURE_SNAPSHOT_ID)`` — the exact call the API's posture loader makes.

The test this replaces searched connector *source* for the sentinel string,
and passed on all four cloud connectors after they were wired, because a
connector that imports the shared constant does not contain the literal. A
detector that only recognises the hardcoded spelling recognises the wrong
one, and a source-reading test can never notice the code does not run.

Three properties are asserted per provider, matching the three rules the
collectors are written to:

* a reachable provider yields a snapshot in the shape its resolver reads;
* an unreadable part of the estate comes back ``partial`` with a note naming
  what was missed, never as a smaller snapshot that looks complete;
* an empty collection is partial with a reason, because zero principals
  means a lost read permission far more often than an empty estate.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from app.connectors.azure_entra import AzureEntraConnector
from app.connectors.github import GitHubConnector
from app.connectors.posture import POSTURE_SNAPSHOT_ID, Collected


class FakeResponse:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = json.dumps(self._payload)

    def json(self) -> Any:
        return self._payload


class FakeClient:
    """Routes a request by substring match against a table of responses.

    Substring rather than exact match because the collectors build URLs with
    page tokens and query parameters; a test pinning whole URLs would fail
    on a pagination change that broke nothing. Longest fragment wins so a
    specific route can sit alongside a general one.
    """

    def __init__(self, routes: dict[str, Any], default: Any = None) -> None:
        self._routes = routes
        self._default = default if default is not None else FakeResponse(404, {"message": "no stub route"})
        self.requested: list[str] = []

    def _match(self, url: str) -> Any:
        best: tuple[int, Any] | None = None
        for fragment, response in self._routes.items():
            if fragment in url and (best is None or len(fragment) > best[0]):
                best = (len(fragment), response)
        return best[1] if best else self._default

    async def get(self, url: str, headers: Any = None, params: Any = None) -> Any:
        self.requested.append(url)
        return self._match(url)

    async def post(self, url: str, headers: Any = None, json: Any = None) -> Any:
        self.requested.append(url)
        return self._match(url)

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None


class FakeHttpx:
    """Stands in for the ``httpx`` module a connector imported.

    The connectors open their own ``httpx.AsyncClient(...)`` inside the
    method under test, so the seam is the module attribute rather than the
    client object. ``HTTPStatusError`` is carried through because one
    connector catches it by name.
    """

    HTTPStatusError = __import__("httpx").HTTPStatusError

    def __init__(self, client: FakeClient) -> None:
        self._client = client

    def AsyncClient(self, *args: Any, **kwargs: Any) -> FakeClient:  # noqa: N802 — mirrors httpx
        return self._client


async def _noop(*args: Any, **kwargs: Any) -> str:
    """Stands in for a connector's ``_authenticate`` so no token is minted."""
    return "test-token"


# --------------------------------------------------------------------------
# Collected: the contract every collector reports its gaps through
# --------------------------------------------------------------------------


def test_noting_a_gap_marks_the_snapshot_partial() -> None:
    """The flag and the reason are one operation on purpose.

    Earlier versions of this idea in the tree had a notes list that some
    callers filled and no caller read. Being able to set them separately is
    exactly what lets a snapshot carry a reason and still report complete.
    """
    collected = Collected(snapshot={"principals": []})
    assert collected.partial is False
    assert collected.notes == []

    collected.note("the second page of role assignments returned 403")

    assert collected.partial is True
    assert collected.notes == ["the second page of role assignments returned 403"]


def test_envelope_carries_the_gap_alongside_the_snapshot() -> None:
    """``partial`` travelling in the same envelope as the data is what lets
    a triage surface render "incomplete, here is why" instead of rendering
    a gap as an absence."""
    collected = Collected(snapshot={"principals": []})
    collected.note("page 2 of 7 returned 403")

    envelope = collected.to_resource_config()

    assert envelope["snapshot"] == {"principals": []}
    assert envelope["partial"] is True
    assert envelope["collection_notes"] == ["page 2 of 7 returned 403"]


# --------------------------------------------------------------------------
# Azure (Entra ID directory roles)
# --------------------------------------------------------------------------


def _entra(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> AzureEntraConnector:
    from app.connectors import azure_entra

    monkeypatch.setattr(azure_entra, "httpx", FakeHttpx(client))
    connector = AzureEntraConnector("tenant-1", "client-1", "secret-1")
    monkeypatch.setattr(connector, "_authenticate", _noop)
    return connector


@pytest.mark.asyncio
async def test_entra_sentinel_returns_a_resolver_shaped_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(
        {
            "roleDefinitions": FakeResponse(
                200,
                {
                    "value": [
                        {
                            "id": "role-ga",
                            "displayName": "Global Administrator",
                            "rolePermissions": [
                                {
                                    "allowedResourceActions": ["microsoft.directory/users/delete"],
                                    "excludedResourceActions": [],
                                }
                            ],
                        }
                    ]
                },
            ),
            "roleAssignments": FakeResponse(
                200,
                {"value": [{"id": "ra-1", "principalId": "user-1", "roleDefinitionId": "role-ga"}]},
            ),
            "directoryObjects/user-1": FakeResponse(200, {"@odata.type": "#microsoft.graph.user", "displayName": "Ada"}),
        }
    )
    connector = _entra(monkeypatch, client)

    envelope = await connector.get_resource_config(POSTURE_SNAPSHOT_ID)
    snapshot = envelope["snapshot"]

    assert [p["id"] for p in snapshot["principals"]] == ["user-1"]
    assert snapshot["principals"][0]["name"] == "Ada"
    assert snapshot["principals"][0]["type"] == "user"
    assert snapshot["role_definitions"][0]["permissions"][0]["actions"] == ["microsoft.directory/users/delete"]
    # Tenant-wide unless an administrative unit narrows it.
    assert snapshot["role_assignments"][0]["scope"] == "/"


@pytest.mark.asyncio
async def test_entra_types_a_service_principal_distinctly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A service principal holding a directory role is the shape that gets
    missed in review, so the type has to survive collection."""
    client = FakeClient(
        {
            "roleDefinitions": FakeResponse(200, {"value": []}),
            "roleAssignments": FakeResponse(200, {"value": [{"id": "ra-2", "principalId": "sp-9", "roleDefinitionId": "role-ga"}]}),
            "directoryObjects/sp-9": FakeResponse(200, {"@odata.type": "#microsoft.graph.servicePrincipal", "displayName": "ci-deployer"}),
        }
    )
    connector = _entra(monkeypatch, client)

    snapshot = (await connector.get_resource_config(POSTURE_SNAPSHOT_ID))["snapshot"]

    assert snapshot["principals"][0]["type"] == "servicePrincipal"
    assert snapshot["principals"][0]["name"] == "ci-deployer"


@pytest.mark.asyncio
async def test_entra_truncated_assignment_read_is_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing page of role assignments is a privileged identity the
    resolver would otherwise report as unprivileged."""
    client = FakeClient(
        {
            "roleDefinitions": FakeResponse(200, {"value": []}),
            "roleAssignments": FakeResponse(403, {"error": {"message": "Insufficient privileges"}}),
        }
    )
    connector = _entra(monkeypatch, client)

    envelope = await connector.get_resource_config(POSTURE_SNAPSHOT_ID)

    assert envelope["partial"] is True
    assert any("role assignments" in note and "403" in note for note in envelope["collection_notes"])


@pytest.mark.asyncio
async def test_entra_records_the_resource_rbac_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """An identity with no directory role may still own a subscription.

    A reader who takes "no permissions found" for "harmless" has made the
    misreading that costs an incident, so the snapshot states the limit of
    its own scope rather than leaving it to be inferred.
    """
    client = FakeClient(
        {
            "roleDefinitions": FakeResponse(200, {"value": []}),
            "roleAssignments": FakeResponse(200, {"value": []}),
        }
    )
    connector = _entra(monkeypatch, client)

    envelope = await connector.get_resource_config(POSTURE_SNAPSHOT_ID)
    notes = " ".join(envelope["collection_notes"]).lower()

    assert envelope["partial"] is True
    assert "resource rbac" in notes
    assert "subscription" in notes


@pytest.mark.asyncio
async def test_entra_refuses_a_non_sentinel_resource_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returning ``{}`` would read as "this resource has no settings"."""
    connector = _entra(monkeypatch, FakeClient({}))
    with pytest.raises(NotImplementedError):
        await connector.get_resource_config("some-directory-object-id")


# --------------------------------------------------------------------------
# GitHub
# --------------------------------------------------------------------------


def _github(monkeypatch: pytest.MonkeyPatch, client: FakeClient) -> GitHubConnector:
    from app.connectors import github as github_connector

    monkeypatch.setattr(github_connector, "httpx", FakeHttpx(client))
    return GitHubConnector("acme", "token")


@pytest.mark.asyncio
async def test_github_org_owner_gets_admin_on_every_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without the membership read, the most privileged identities in an
    organisation resolve to whatever their team happened to grant."""
    client = FakeClient(
        {
            "/orgs/acme/members": FakeResponse(200, [{"login": "owner-ann"}, {"login": "dev-bob"}]),
            "/orgs/acme/teams/platform/members": FakeResponse(200, [{"login": "dev-bob"}]),
            "/orgs/acme/teams/platform/repos": FakeResponse(200, [{"full_name": "acme/api", "permissions": {"pull": True, "push": True}}]),
            "/orgs/acme/teams": FakeResponse(200, [{"slug": "platform"}]),
            "/orgs/acme/repos": FakeResponse(200, [{"full_name": "acme/api", "name": "api"}, {"full_name": "acme/web", "name": "web"}]),
            "/orgs/acme/memberships/owner-ann": FakeResponse(200, {"role": "admin"}),
            "/orgs/acme/memberships/dev-bob": FakeResponse(200, {"role": "member"}),
            "/collaborators": FakeResponse(200, []),
        }
    )
    connector = _github(monkeypatch, client)

    snapshot = (await connector.get_resource_config(POSTURE_SNAPSHOT_ID))["snapshot"]

    owner_grants = {(g["repository_id"], g["level"]) for g in snapshot["grants"] if g["principal_id"] == "owner-ann"}
    assert owner_grants == {("acme/api", "admin"), ("acme/web", "admin")}

    team_grants = {(g["repository_id"], g["level"]) for g in snapshot["grants"] if g["principal_id"] == "team:platform"}
    assert team_grants == {("acme/api", "push")}

    ann = next(p for p in snapshot["principals"] if p["id"] == "owner-ann")
    assert ann["org_role"] == "admin"


@pytest.mark.asyncio
async def test_github_cumulative_permission_block_reads_as_the_strongest_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GitHub returns ``{"admin": true, "push": true, "pull": true}`` rather
    than one level, and the booleans are cumulative — so the strongest true
    one is the answer, not the first."""
    client = FakeClient(
        {
            "/orgs/acme/members": FakeResponse(200, []),
            "/orgs/acme/teams": FakeResponse(200, []),
            "/orgs/acme/repos": FakeResponse(200, [{"full_name": "acme/api", "name": "api"}]),
            "/repos/acme/api/collaborators": FakeResponse(
                200,
                [{"login": "dev-bob", "permissions": {"pull": True, "triage": True, "push": True, "admin": True}}],
            ),
        }
    )
    connector = _github(monkeypatch, client)

    snapshot = (await connector.get_resource_config(POSTURE_SNAPSHOT_ID))["snapshot"]

    assert [g["level"] for g in snapshot["grants"]] == ["admin"]


@pytest.mark.asyncio
async def test_github_unreadable_membership_is_a_note_not_a_silent_demotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 403 on the membership read must not quietly turn an owner into a
    member — that under-states the blast radius of the account holding the
    most of it."""
    client = FakeClient(
        {
            "/orgs/acme/members": FakeResponse(200, [{"login": "owner-ann"}]),
            "/orgs/acme/teams": FakeResponse(200, []),
            "/orgs/acme/repos": FakeResponse(200, []),
            "/orgs/acme/memberships/owner-ann": FakeResponse(403, {"message": "Forbidden"}),
        }
    )
    connector = _github(monkeypatch, client)

    envelope = await connector.get_resource_config(POSTURE_SNAPSHOT_ID)
    notes = " ".join(envelope["collection_notes"])

    assert envelope["partial"] is True
    assert "owner-ann" in notes
    assert "403" in notes


@pytest.mark.asyncio
async def test_github_empty_org_is_partial_with_a_scope_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeClient(
        {
            "/orgs/acme/members": FakeResponse(200, []),
            "/orgs/acme/teams": FakeResponse(200, []),
            "/orgs/acme/repos": FakeResponse(200, []),
        }
    )
    connector = _github(monkeypatch, client)

    envelope = await connector.get_resource_config(POSTURE_SNAPSHOT_ID)

    assert envelope["partial"] is True
    assert "read:org" in " ".join(envelope["collection_notes"])


@pytest.mark.asyncio
async def test_github_still_answers_a_repo_resource_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sentinel is an addition, not a replacement: the pre-existing
    per-repository config read has to keep working."""
    client = FakeClient({"/repos/acme/api": FakeResponse(404, {"message": "Not Found"})})
    connector = _github(monkeypatch, client)

    result = await connector.get_resource_config("acme/api")

    assert result.get("snapshot_freshness") == "unavailable"


# --------------------------------------------------------------------------
# The contract every implementation has to keep
# --------------------------------------------------------------------------


def test_every_implementation_matches_the_base_signature() -> None:
    """``at_ts`` is optional in the base class and three connectors required
    a second positional ``ts``.

    Nothing broke, because both call sites happened to pass positionally —
    but the base's own docstring tells a caller that omitting the timestamp
    means "latest known", and following that advice raised TypeError on
    AWS, Okta and GitHub. A contract that only works if you read the
    implementations is not a contract.
    """
    import inspect

    from app.connectors import CONNECTOR_REGISTRY
    from app.connectors.base import BaseConnector

    expected = inspect.signature(BaseConnector.get_resource_config)
    drifted: list[str] = []
    for connector_id, cls in sorted(CONNECTOR_REGISTRY.items()):
        impl = cls.__dict__.get("get_resource_config")
        if impl is None:
            continue
        if inspect.signature(impl) != expected:
            drifted.append(f"{connector_id}: {inspect.signature(impl)}")

    assert not drifted, "get_resource_config signatures differ from BaseConnector's:\n  " + "\n  ".join(drifted)


# --------------------------------------------------------------------------
# AWS
# --------------------------------------------------------------------------


class FakeIam:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self._pages = pages
        self.calls = 0

    def get_account_authorization_details(self, **kwargs: Any) -> dict[str, Any]:
        page = self._pages[min(self.calls, len(self._pages) - 1)]
        self.calls += 1
        return page


class FakeSession:
    def __init__(self, clients: dict[str, Any]) -> None:
        self._clients = clients

    def client(self, name: str, **kwargs: Any) -> Any:
        if name not in self._clients:
            raise RuntimeError(f"no stub client for {name!r}")
        return self._clients[name]


_EMPTY_IAM_PAGE: dict[str, Any] = {
    "UserDetailList": [],
    "GroupDetailList": [],
    "RoleDetailList": [],
    "Policies": [],
    "IsTruncated": False,
}


@pytest.mark.asyncio
async def test_aws_collects_users_groups_and_the_default_policy_version() -> None:
    from app.connectors.posture import aws as aws_posture

    iam = FakeIam(
        [
            {
                "UserDetailList": [
                    {
                        "Arn": "arn:aws:iam::111122223333:user/ada",
                        "UserName": "ada",
                        "GroupList": ["engineers"],
                        "AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
                    }
                ],
                "GroupDetailList": [{"Arn": "arn:aws:iam::111122223333:group/engineers", "GroupName": "engineers"}],
                "RoleDetailList": [],
                "Policies": [
                    {
                        "Arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                        "PolicyName": "ReadOnlyAccess",
                        "DefaultVersionId": "v2",
                        "PolicyVersionList": [
                            {
                                "VersionId": "v1",
                                "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]},
                            },
                            {
                                "VersionId": "v2",
                                "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
                            },
                        ],
                    }
                ],
                "IsTruncated": False,
            }
        ]
    )

    collected = await aws_posture.collect(FakeSession({"iam": iam}))
    snapshot = collected.snapshot

    ada = next(p for p in snapshot["principals"] if p["id"].endswith("user/ada"))
    assert ada["attached_policies"] == ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
    assert ada["groups"] == ["arn:aws:iam::111122223333:group/engineers"]

    policy = next(p for p in snapshot["policies"] if p["id"].endswith("ReadOnlyAccess"))
    # The non-default version is the one that grants s3:*; reading it would
    # over-state what the principal can do.
    assert policy["document"]["Statement"][0]["Action"] == "s3:GetObject"


@pytest.mark.asyncio
async def test_aws_carries_the_permissions_boundary_through() -> None:
    """The field 2.5 exists to model. Absent is not the same as "a boundary
    that allows everything", so it has to arrive at the resolver."""
    from app.connectors.posture import aws as aws_posture

    iam = FakeIam(
        [
            {
                **_EMPTY_IAM_PAGE,
                "UserDetailList": [
                    {
                        "Arn": "arn:aws:iam::111122223333:user/frank",
                        "UserName": "frank",
                        "PermissionsBoundary": {"PermissionsBoundaryArn": "arn:aws:iam::111122223333:policy/DevBoundary"},
                    },
                    {"Arn": "arn:aws:iam::111122223333:user/gina", "UserName": "gina"},
                ],
            }
        ]
    )

    snapshot = (await aws_posture.collect(FakeSession({"iam": iam}))).snapshot
    by_name = {p["name"]: p for p in snapshot["principals"]}

    assert by_name["frank"]["permissions_boundary"] == "arn:aws:iam::111122223333:policy/DevBoundary"
    assert by_name["gina"]["permissions_boundary"] is None


@pytest.mark.asyncio
async def test_aws_missing_organizations_access_is_recorded() -> None:
    """Service control policies cap everything beneath them, so a collection
    that could not read them must say so — otherwise a principal the SCP
    blocks resolves as able to act."""
    from app.connectors.posture import aws as aws_posture

    class DeniedOrgs:
        def list_policies(self, **kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("AccessDeniedException: organizations:ListPolicies")

    collected = await aws_posture.collect(FakeSession({"iam": FakeIam([_EMPTY_IAM_PAGE]), "organizations": DeniedOrgs()}))

    assert collected.partial is True
    assert any("service control policies not read" in note for note in collected.notes)


@pytest.mark.asyncio
async def test_aws_empty_estate_names_the_likely_permission() -> None:
    from app.connectors.posture import aws as aws_posture

    collected = await aws_posture.collect(FakeSession({"iam": FakeIam([_EMPTY_IAM_PAGE])}))

    assert collected.partial is True
    assert any("GetAccountAuthorizationDetails" in note for note in collected.notes)


@pytest.mark.asyncio
async def test_aws_records_that_resource_policies_are_not_collected() -> None:
    """A grant made by a bucket or key policy will not appear, and the
    snapshot says so rather than reading as a complete picture."""
    from app.connectors.posture import aws as aws_posture

    collected = await aws_posture.collect(FakeSession({"iam": FakeIam([_EMPTY_IAM_PAGE])}))

    assert any("resource-based policies" in note for note in collected.notes)
