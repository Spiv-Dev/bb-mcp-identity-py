"""ASGI middleware that puts a server behind the broker.

    app = IdentityMiddleware(
        mcp.streamable_http_app(),
        verifier,
        mcp_path="/mcp",
        legacy_bearer_ok=my_existing_validator,     # enabled mode only; None in required mode
        mint_internal_token=my_internal_token,      # optional: rewrite Authorization for the inner auth layer
    )

Behaviour on ``mcp_path``:
  * no bearer                      -> 401 + WWW-Authenticate (resource_metadata=...)
  * broker token, verified         -> request continues; ``scope["state"]["identity_principal"]`` is set;
                                      if ``mint_internal_token`` is given, the Authorization header is
                                      replaced with the server's own internal token for that principal
  * broker token, denied           -> 401 (the reason is logged, never sent)
  * not a broker token, enabled    -> if ``legacy_bearer_ok(bearer)`` is true the request continues
                                      untouched (the server's existing validator runs), else 401
  * not a broker token, required   -> 401

Also serves ``/.well-known/oauth-protected-resource`` and the same document
with the MCP path appended.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from .metadata import protected_resource_metadata, www_authenticate
from .verifier import Deny, Principal, Verifier

log = logging.getLogger("bb_mcp_identity.asgi")

LegacyCheck = Callable[[str], bool]
Minter = Callable[[Principal], str]
Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


def _header(scope: Scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return str(v.decode("latin-1"))
    return None


def _bearer(scope: Scope) -> str | None:
    h = _header(scope, b"authorization")
    if not h:
        return None
    parts = h.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


class IdentityMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        verifier: Verifier,
        *,
        mcp_path: str = "/mcp",
        legacy_bearer_ok: LegacyCheck | None = None,
        mint_internal_token: Minter | None = None,
        scopes_supported: list[str] | None = None,
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.mcp_path = mcp_path.rstrip("/") or "/"
        self.legacy_bearer_ok = legacy_bearer_ok
        self.mint_internal_token = mint_internal_token
        self.scopes_supported = scopes_supported or []
        self.denied = 0
        self.verified = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not self.verifier.config.enabled:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path in ("/.well-known/oauth-protected-resource", f"/.well-known/oauth-protected-resource{self.mcp_path}"):
            await self._json(send, 200, protected_resource_metadata(self.verifier.config, self.scopes_supported))
            return
        if not (path == self.mcp_path or path.startswith(self.mcp_path + "/")):
            await self.app(scope, receive, send)
            return

        bearer = _bearer(scope)
        if bearer is None:
            await self._challenge(send, "missing_bearer")
            return
        try:
            principal = self.verifier.verify(bearer)
        except Deny as d:
            if not d.ours and not self.verifier.config.required and self.legacy_bearer_ok is not None and self.legacy_bearer_ok(bearer):
                await self.app(scope, receive, send)
                return
            self.denied += 1
            log.info("identity: bearer refused (%s)", d.reason)
            await self._challenge(send, d.reason)
            return

        self.verified += 1
        state = scope.setdefault("state", {})
        state["identity_principal"] = principal
        if self.mint_internal_token is not None:
            internal = self.mint_internal_token(principal)
            headers = [(k, v) for k, v in scope.get("headers", []) if k.lower() != b"authorization"]
            headers.append((b"authorization", f"Bearer {internal}".encode("latin-1")))
            scope = dict(scope, headers=headers)
        await self.app(scope, receive, send)

    async def _challenge(self, send: Send, reason: str) -> None:
        err = "invalid_token" if reason != "missing_bearer" else None
        headers = [
            (b"www-authenticate", www_authenticate(self.verifier.config, error=err).encode("latin-1")),
            (b"content-type", b"application/json; charset=utf-8"),
            (b"cache-control", b"no-store"),
        ]
        body = json.dumps({"error": err or "unauthorized", "error_description": "authorization required"}).encode()
        await send({"type": "http.response.start", "status": 401, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def _json(self, send: Send, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json; charset=utf-8"), (b"cache-control", b"no-store")],
            }
        )
        await send({"type": "http.response.body", "body": raw})
