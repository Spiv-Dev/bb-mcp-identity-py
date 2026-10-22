from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from bb_mcp_identity import IdentityMiddleware, Principal, Verifier

from .conftest import RESOURCE, SUB, StubBroker, make_config


async def echo_app(scope: dict, receive: Any, send: Any) -> None:
    """Echoes the Authorization header and the principal the middleware set."""
    auth = ""
    for k, v in scope.get("headers", []):
        if k == b"authorization":
            auth = v.decode()
    principal = scope.get("state", {}).get("identity_principal")
    body = json.dumps(
        {"authorization": auth, "principal": None if principal is None else principal.sub, "tier": getattr(principal, "tier", None)}
    ).encode()
    await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body", "body": body})


def verifier(broker: StubBroker, mode: str) -> Verifier:
    v = Verifier(make_config(broker, mode))
    v.keys.fetch()
    v.snapshot.fetch()
    return v


async def call(app: Any, path: str, bearer: str | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        return await c.post(path, headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})


@pytest.mark.asyncio
async def test_challenge_and_metadata(broker: StubBroker) -> None:
    app = IdentityMiddleware(echo_app, verifier(broker, "required"), mcp_path="/mcp", scopes_supported=["t:read", "t:write"])
    r = await call(app, "/mcp")
    assert r.status_code == 401
    www = r.headers["www-authenticate"]
    assert 'resource_metadata="https://testapp-mcp.example.test/.well-known/oauth-protected-resource"' in www
    assert "realm=" in www
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        meta = (await c.get("/.well-known/oauth-protected-resource")).json()
        meta2 = (await c.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert meta == meta2
    assert meta["resource"] == RESOURCE
    assert meta["authorization_servers"] == [broker.issuer]
    assert meta["scopes_supported"] == ["mcp", "t:read", "t:write"]


@pytest.mark.asyncio
async def test_broker_token_sets_principal_and_rewrites_authorization(broker: StubBroker) -> None:
    def mint_internal(p: Principal) -> str:
        return f"internal-for-{p.sub}-{p.tier}"

    app = IdentityMiddleware(echo_app, verifier(broker, "required"), mint_internal_token=mint_internal)
    r = await call(app, "/mcp", broker.mint())
    assert r.status_code == 200
    body = r.json()
    assert body["principal"] == SUB
    assert body["tier"] == "Admin"
    assert body["authorization"] == f"Bearer internal-for-{SUB}-Admin"


@pytest.mark.asyncio
async def test_required_mode_refuses_legacy_tokens(broker: StubBroker) -> None:
    app = IdentityMiddleware(echo_app, verifier(broker, "required"), legacy_bearer_ok=lambda _b: True)
    r = await call(app, "/mcp", "tok_legacy_personal_token_xxxxxxxxxxxxxxxx")
    assert r.status_code == 401
    assert 'error="invalid_token"' in r.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_enabled_mode_lets_legacy_tokens_through_to_the_server(broker: StubBroker) -> None:
    app = IdentityMiddleware(echo_app, verifier(broker, "enabled"), legacy_bearer_ok=lambda b: b.startswith("tok_"))
    ok = await call(app, "/mcp", "tok_legacy_personal_token_xxxxxxxxxxxxxxxx")
    assert ok.status_code == 200
    assert ok.json()["principal"] is None
    bad = await call(app, "/mcp", "zzz_not_a_known_token")
    assert bad.status_code == 401
    # A broker token that is denied never falls through, even in enabled mode.
    denied = await call(app, "/mcp", broker.mint(aud="https://other.example.test/mcp"))
    assert denied.status_code == 401


@pytest.mark.asyncio
async def test_other_paths_and_off_mode_are_untouched(broker: StubBroker) -> None:
    app = IdentityMiddleware(echo_app, verifier(broker, "required"))
    r = await call(app, "/healthz")
    assert r.status_code == 200
    off = IdentityMiddleware(echo_app, Verifier(make_config(broker, "off")))
    r2 = await call(off, "/mcp")
    assert r2.status_code == 200
