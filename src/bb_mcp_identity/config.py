"""Settings for a verifier, read from ``<PREFIX>_IDENTITY_*`` environment
variables so every MCP server configures it the same way.

    DEV_IDENTITY_MODE=enabled            off | enabled | required
    DEV_IDENTITY_ISSUER=https://id.bakerbaynes.com/r/development
    DEV_IDENTITY_RESOURCE=https://development-mcp.bakerbaynes.com/mcp
    DEV_IDENTITY_VERIFIER_TOKEN=bbv_development_...     (snapshot reads)
    DEV_IDENTITY_SNAPSHOT_URL=http://127.0.0.1:8775/r/development/snapshot   (optional)
    DEV_IDENTITY_JWKS_URL=http://127.0.0.1:8775/.well-known/jwks.json       (optional)
    DEV_IDENTITY_SNAPSHOT_CACHE=/var/lib/bb-development-mcp/identity-snapshot.json
    DEV_IDENTITY_PINNED_JWKS={"keys":[...]}             (optional, offline verification)
    DEV_IDENTITY_SERVICE_PRINCIPALS=/etc/.../service-principals   (optional)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Literal

Mode = Literal["off", "enabled", "required"]


class ConfigError(ValueError):
    """A required identity setting is missing or malformed."""


def _issuer_base(issuer: str) -> tuple[str, str]:
    """Split ``https://id.example/r/<app>`` into (base, app)."""
    marker = "/r/"
    idx = issuer.rfind(marker)
    if idx < 0:
        raise ConfigError(f"issuer must look like https://host/r/<app>: {issuer!r}")
    base = issuer[:idx]
    app = issuer[idx + len(marker) :].strip("/")
    if not app or "/" in app:
        raise ConfigError(f"issuer must end with /r/<app>: {issuer!r}")
    return base, app


@dataclass(frozen=True)
class IdentityConfig:
    mode: Mode
    issuer: str
    resource: str
    app: str
    jwks_url: str
    snapshot_url: str
    verifier_token: str | None
    snapshot_cache_path: str | None
    service_principals_path: str | None
    pinned_jwks: dict[str, Any] | None = None
    poll_interval_s: int = 60
    jwks_ttl_s: int = 300
    leeway_s: int = 30
    http_timeout_s: float = 5.0
    realm: str = "bb-mcp"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    @property
    def required(self) -> bool:
        return self.mode == "required"

    @classmethod
    def from_env(cls, prefix: str, *, realm: str | None = None, environ: dict[str, str] | None = None) -> IdentityConfig:
        env = os.environ if environ is None else environ
        p = f"{prefix}_IDENTITY_"
        mode = (env.get(p + "MODE") or "off").strip().lower()
        if mode not in ("off", "enabled", "required"):
            raise ConfigError(f"{p}MODE must be off, enabled or required (got {mode!r})")
        issuer = (env.get(p + "ISSUER") or "").strip().rstrip("/")
        resource = (env.get(p + "RESOURCE") or "").strip()
        if mode != "off":
            if not issuer:
                raise ConfigError(f"{p}ISSUER is required when {p}MODE={mode}")
            if not resource:
                raise ConfigError(f"{p}RESOURCE is required when {p}MODE={mode}")
        base, app = _issuer_base(issuer) if issuer else ("", "")
        pinned_raw = env.get(p + "PINNED_JWKS")
        pinned = None
        if pinned_raw:
            try:
                pinned = json.loads(pinned_raw)
            except json.JSONDecodeError as exc:
                raise ConfigError(f"{p}PINNED_JWKS is not JSON: {exc}") from exc
            if not isinstance(pinned, dict) or not isinstance(pinned.get("keys"), list):
                raise ConfigError(f"{p}PINNED_JWKS must be a JWKS object with a keys array")
        return cls(
            mode=mode,  # type: ignore[arg-type]
            issuer=issuer,
            resource=resource.rstrip("/") if resource.endswith("/") and resource.count("/") > 3 else resource,
            app=app,
            jwks_url=(env.get(p + "JWKS_URL") or (f"{base}/.well-known/jwks.json" if base else "")).strip(),
            snapshot_url=(env.get(p + "SNAPSHOT_URL") or (f"{issuer}/snapshot" if issuer else "")).strip(),
            verifier_token=(env.get(p + "VERIFIER_TOKEN") or "").strip() or None,
            snapshot_cache_path=(env.get(p + "SNAPSHOT_CACHE") or "").strip() or None,
            service_principals_path=(env.get(p + "SERVICE_PRINCIPALS") or "").strip() or None,
            pinned_jwks=pinned,
            poll_interval_s=int(env.get(p + "POLL_INTERVAL_S") or 60),
            jwks_ttl_s=int(env.get(p + "JWKS_TTL_S") or 300),
            leeway_s=int(env.get(p + "LEEWAY_S") or 30),
            http_timeout_s=float(env.get(p + "HTTP_TIMEOUT_S") or 5.0),
            realm=realm or f"{prefix.lower()}-mcp",
        )
