"""A stub broker: an ES256 key pair, a JWKS endpoint, a snapshot endpoint with
verifier-token auth and ETag, and a minter for tokens. All synthetic."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from bb_mcp_identity import IdentityConfig

APP = "testapp"
RESOURCE = "https://testapp-mcp.example.test/mcp"
VERIFIER_TOKEN = "bbv_testapp_verifier_token_value_0000000000"
SUB = "005000000000001AAA"


class StubBroker:
    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.kid = "bbid-test-1"
        pub_numbers = self.private.public_key().public_numbers()
        self.jwk: dict[str, Any] = {
            "kty": "EC",
            "crv": "P-256",
            "x": jwt.utils.base64url_encode(pub_numbers.x.to_bytes(32, "big")).decode(),
            "y": jwt.utils.base64url_encode(pub_numbers.y.to_bytes(32, "big")).decode(),
            "kid": self.kid,
            "alg": "ES256",
            "use": "sig",
        }
        self.snapshot: dict[str, Any] = {
            "version": 1,
            "generated_at": int(time.time() * 1000),
            "source": "salesforce",
            "stale_after_s": 1200,
            "app": APP,
            "resource": RESOURCE,
            "subjects": {SUB: {"status": "active", "active": True, "not_before": 0, "tier": "Admin", "scope": "t:read t:write"}},
        }
        self.jwks_hits = 0
        self.snapshot_hits = 0
        self.base_url = ""
        self._server: HTTPServer | None = None

    @property
    def issuer(self) -> str:
        return f"{self.base_url}/r/{APP}"

    def pem(self) -> str:
        return self.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()

    def mint(self, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": RESOURCE,
            "sub": SUB,
            "preferred_username": "alice@example.invalid",
            "app": APP,
            "tier": "Admin",
            "scope": "t:read t:write",
            "client_id": "client-1",
            "auth_time": now,
            "iat": now,
            "exp": now + 600,
            "jti": "jti-1",
        }
        claims.update(overrides)
        headers = {"kid": overrides.pop("_kid", self.kid), "typ": "at+jwt"}
        alg = overrides.pop("_alg", "ES256")
        key: Any = self.pem() if alg == "ES256" else "hs-secret"
        return jwt.encode(claims, key, algorithm=alg, headers=headers)

    def start(self) -> None:
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:  # silence
                pass

            def _json(self, status: int, body: Any, extra: dict[str, str] | None = None) -> None:
                raw = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                if self.path == "/.well-known/jwks.json":
                    broker.jwks_hits += 1
                    self._json(200, {"keys": [broker.jwk]})
                    return
                if self.path == f"/r/{APP}/snapshot":
                    broker.snapshot_hits += 1
                    if self.headers.get("Authorization") != f"Bearer {VERIFIER_TOKEN}":
                        self._json(401, {"error": "unauthorized"})
                        return
                    etag = f'"{broker.snapshot["version"]}"'
                    if self.headers.get("If-None-Match") == etag:
                        self.send_response(304)
                        self.end_headers()
                        return
                    self._json(200, broker.snapshot, {"ETag": etag})
                    return
                self.send_response(404)
                self.end_headers()

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_port}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


@pytest.fixture
def broker() -> Any:
    b = StubBroker()
    b.start()
    yield b
    b.stop()


def make_config(broker: StubBroker, mode: str = "required", **extra: str) -> IdentityConfig:
    env = {
        "T_IDENTITY_MODE": mode,
        "T_IDENTITY_ISSUER": broker.issuer,
        "T_IDENTITY_RESOURCE": RESOURCE,
        "T_IDENTITY_VERIFIER_TOKEN": VERIFIER_TOKEN,
        "T_IDENTITY_POLL_INTERVAL_S": "3600",
    }
    env.update(extra)
    return IdentityConfig.from_env("T", environ=env)
