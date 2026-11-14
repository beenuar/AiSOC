"""The Teams callback authenticates its caller, and records what it decided.

GHSA-vf98-8367-45mp, F03 and F62.

**F03.** `POST /teams/messages` had no inbound authentication of any kind,
and `_resolve_approver` reads the deciding identity out of
``from.aadObjectId`` -- a Bot Framework envelope field, which our HMAC does
not cover (that signs ``value.action.data``, the card payload we issued). So
anyone who could reach the port could approve or reject a governed response
action under any identity they chose.

The module docstring argued the Bot Framework JWT is "enforced by the
deployment fronting reverse proxy, not by this service". That is a real
deployment pattern and it is not a control this repository can observe --
an operator who exposes the container directly, or whose proxy rule is scoped
to another path, got no authentication at all and nothing said so.

**F62.** `build_audit_sink` located the shared sink by walking
``parents[3] / "slack-bot" / ...`` and fell back to a null sink when it was
absent. In a checkout that path resolves. **In the built image it is
``/slack-bot/app/services/approval_audit.py``**, because the Dockerfile
copies only this service's ``app/`` -- so the shipped container recorded no
approval decisions at all, silently, while every developer running from
source saw them recorded. That pairing is what keeps a defect alive.
"""

from __future__ import annotations

import pathlib

import pytest
from app.main import app
from fastapi.testclient import TestClient

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

CARD_ACTIVITY = {
    "type": "invoke",
    "name": "adaptiveCard/action",
    "value": {"action": {"data": {"verb": "approve", "action_id": "a-1", "case_id": "c-1"}}},
    "from": {"id": "29:anyone", "aadObjectId": "whoever-i-say-i-am"},
    "conversation": {"id": "19:thread"},
}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("AISOC_TEAMS_INBOUND_TOKEN", "the-shared-secret")
    # As a context manager, so startup runs and `app.state` is wired. Without
    # it the route 500s on a missing actions client, which would make the
    # refusal assertions pass for a reason that has nothing to do with auth.
    with TestClient(app) as started:
        yield started


class TestTheCallbackAuthenticatesItsCaller:
    def test_a_callback_with_no_authorization_is_refused(self, client: TestClient) -> None:
        response = client.post("/teams/messages", json=CARD_ACTIVITY)
        assert response.status_code == 401, (
            f"an unauthenticated caller named itself as the approver of a governed action: {response.status_code} {response.text}"
        )

    def test_a_wrong_token_is_refused(self, client: TestClient) -> None:
        response = client.post("/teams/messages", json=CARD_ACTIVITY, headers={"Authorization": "Bearer not-the-secret"})
        assert response.status_code == 401

    def test_the_configured_token_is_accepted(self, client: TestClient) -> None:
        """Positive control.

        A check that refused everybody would satisfy both tests above and make
        every Teams approval impossible -- the fail-closed shape this
        repository has shipped before, where a control withheld every grant on
        every deployment and passed its negative test perfectly.

        The decision itself fails here (the HMAC over the card payload is not
        valid in this fixture) and that is the point: it got *past*
        authentication and was judged on its own merits.
        """
        response = client.post("/teams/messages", json=CARD_ACTIVITY, headers={"Authorization": "Bearer the-shared-secret"})
        assert response.status_code == 200
        assert response.json()["decision"] == "rejected_invalid_signature"

    def test_a_bare_token_without_the_bearer_prefix_is_accepted(self, client: TestClient) -> None:
        """Second positive control.

        Proxies and channel configurations differ on whether they prefix the
        scheme. Rejecting the bare form would be an authentication failure an
        operator cannot distinguish from a wrong secret.
        """
        response = client.post("/teams/messages", json=CARD_ACTIVITY, headers={"Authorization": "the-shared-secret"})
        assert response.status_code == 200

    def test_an_unset_token_in_production_refuses_rather_than_opens(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unconfigured must not mean unauthenticated.

        503 rather than 401: the caller did nothing wrong, the deployment is
        incomplete, and the two need different answers.
        """
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.delenv("AISOC_TEAMS_INBOUND_TOKEN", raising=False)
        with TestClient(app) as started:
            response = started.post("/teams/messages", json=CARD_ACTIVITY)
        assert response.status_code == 503
        assert "AISOC_TEAMS_INBOUND_TOKEN" in response.json()["detail"]

    def test_a_development_environment_may_run_without_a_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Third positive control.

        A local run with no secret has to keep working, or the refusal above
        is a reason to set `ENVIRONMENT=production` nowhere and lose the
        control everywhere.
        """
        monkeypatch.setenv("ENVIRONMENT", "development")
        monkeypatch.delenv("AISOC_TEAMS_INBOUND_TOKEN", raising=False)
        with TestClient(app) as started:
            response = started.post("/teams/messages", json=CARD_ACTIVITY)
        assert response.status_code == 200


class TestTheAuditSinkSurvivesBeingBuilt:
    def test_the_sink_is_real_and_not_a_null_object(self) -> None:
        from app.services.aisoc_clients import build_audit_sink
        from app.services.approval_audit import StructlogAuditSink

        assert isinstance(build_audit_sink(), StructlogAuditSink)

    def test_it_does_not_reach_outside_this_service_s_build_context(self) -> None:
        """The defect, stated as the property that prevents it.

        `aisoc_clients` must not locate the audit sink by walking up to a
        sibling service's source tree: that directory is not in this service's
        Docker build context, so the path resolves in a checkout and not in
        the image.
        """
        import ast

        path = REPO_ROOT / "services" / "teams-bot" / "app" / "services" / "aisoc_clients.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        fn = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "build_audit_sink")
        # Strip the docstring before looking: it *describes* the old path on
        # purpose, and an assertion that matched its own explanation would
        # fail forever for the wrong reason.
        body = fn.body[1:] if ast.get_docstring(fn) else fn.body
        code = "\n".join(ast.unparse(stmt) for stmt in body)
        assert "parents" not in code, "the sink is located by walking outside the build context again"
        assert "NullAuditSink" not in code, (
            "a null-sink fallback is back; the only thing it can express is 'audit nothing', which is what shipped"
        )

    def test_the_vendored_copy_has_not_drifted(self) -> None:
        """One concept, two files, and they must agree.

        Vendored rather than imported for the same reason as `cors.py` and
        `tenant_scope.py`: each service builds with its own directory as the
        Docker context. The cost of vendoring is drift, so it is pinned.
        """
        upstream = (REPO_ROOT / "services" / "slack-bot" / "app" / "services" / "approval_audit.py").read_text(encoding="utf-8")
        vendored = (REPO_ROOT / "services" / "teams-bot" / "app" / "services" / "approval_audit.py").read_text(encoding="utf-8")
        marker = "# --- vendored content ---\n"
        assert marker in vendored, "the vendored copy lost its banner"
        body = vendored.split(marker, 1)[1]
        upstream_body = upstream[upstream.index('"""', upstream.index('"""') + 3) + 3 :].lstrip("\n")
        assert body == upstream_body, (
            "services/teams-bot/app/services/approval_audit.py has drifted from the slack-bot "
            "copy; re-vendor it rather than editing one side"
        )
