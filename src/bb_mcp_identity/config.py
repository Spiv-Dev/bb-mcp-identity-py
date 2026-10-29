"""Settings for a verifier, read from ``<PREFIX>_IDENTITY_*`` environment
variables so every MCP server configures it the same way.

    DEV_IDENTITY_MODE=enabled            off | enabled | required
    DEV_IDENTITY_ISSUER=https://id.bakerbaynes.com/r/development
    DEV_IDENTITY_RESOURCE=https://development-mcp.bakerbaynes.com/mcp
    DEV_IDENTITY_VERIFIER_TOKEN=bbv_development_...     (snapshot reads; required unless off)
    DEV_IDENTITY_SNAPSHOT_URL=http://127.0.0.1:8775/r/development/snapshot   (optional)
    DEV_IDENTITY_JWKS_URL=http://127.0.0.1:8775/.well-known/jwks.json       (optional)
    DEV_IDENTITY_SNAPSHOT_CACHE=/var/lib/bb-development-mcp/identity-snapshot.json
    DEV_IDENTITY_PINNED_JWKS={"keys":[...]}             (optional, offline verification)
    DEV_IDENTITY_SERVICE_PRINCIPALS=/etc/.../service-principals   (optional)
    DEV_IDENTITY_BREAK_GLASS_SHA256=<64 hex>             (optional; the sealed operator bearer)
    DEV_IDENTITY_BREAK_GLASS_UNTIL=2026-10-28T18:00:00+02:00   (arms it; at most 24 h ahead)
    DEV_IDENTITY_BREAK_GLASS_TIER=Admin                  (required while armed)
    DEV_IDENTITY_BREAK_GLASS_OWNER=<18-char Salesforce Id>   (required while armed)

An empty value counts as unset. The broker URLs must be https, except loopback
(the broker on the same VM) which may be plain http.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from .break_glass import MAX_WINDOW_S, OWNER_PATTERN, UNTIL_PATTERN, BreakGlassConfig

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


_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _assert_broker_url(name: str, url: str) -> None:
    """The broker is reached over https, or over plain http on loopback only."""
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS:
        return
    raise ConfigError(f"{name} must use https (plain http is allowed for loopback only): {url!r}")


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
    break_glass: BreakGlassConfig | None = None
    poll_interval_s: int = 60
    miss_refresh_s: int = 5
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
    def from_env(
        cls, prefix: str, *, realm: str | None = None, environ: dict[str, str] | None = None, now: float | None = None
    ) -> IdentityConfig:
        env = os.environ if environ is None else environ
        p = f"{prefix}_IDENTITY_"
        mode = (env.get(p + "MODE") or "off").strip().lower()
        if mode not in ("off", "enabled", "required"):
            raise ConfigError(f"{p}MODE must be off, enabled or required (got {mode!r})")
        issuer = (env.get(p + "ISSUER") or "").strip().rstrip("/")
        resource = (env.get(p + "RESOURCE") or "").strip()
        verifier_token = (env.get(p + "VERIFIER_TOKEN") or "").strip() or None
        if mode != "off":
            if not issuer:
                raise ConfigError(f"{p}ISSUER is required when {p}MODE={mode}")
            if not resource:
                raise ConfigError(f"{p}RESOURCE is required when {p}MODE={mode}")
            if not verifier_token:
                raise ConfigError(f"{p}VERIFIER_TOKEN is required when {p}MODE={mode}")
        base, app = _issuer_base(issuer) if issuer else ("", "")
        jwks_url = (env.get(p + "JWKS_URL") or (f"{base}/.well-known/jwks.json" if base else "")).strip()
        snapshot_url = (env.get(p + "SNAPSHOT_URL") or (f"{issuer}/snapshot" if issuer else "")).strip()
        if mode != "off":
            _assert_broker_url(f"{p}ISSUER", issuer)
            _assert_broker_url(f"{p}JWKS_URL", jwks_url)
            _assert_broker_url(f"{p}SNAPSHOT_URL", snapshot_url)
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
            jwks_url=jwks_url,
            snapshot_url=snapshot_url,
            verifier_token=verifier_token,
            snapshot_cache_path=(env.get(p + "SNAPSHOT_CACHE") or "").strip() or None,
            service_principals_path=(env.get(p + "SERVICE_PRINCIPALS") or "").strip() or None,
            pinned_jwks=pinned,
            break_glass=_break_glass_from_env(env, p, time.time() if now is None else now),
            poll_interval_s=int(env.get(p + "POLL_INTERVAL_S") or 60),
            miss_refresh_s=int(env.get(p + "MISS_REFRESH_S") or 5),
            jwks_ttl_s=int(env.get(p + "JWKS_TTL_S") or 300),
            leeway_s=int(env.get(p + "LEEWAY_S") or 30),
            http_timeout_s=float(env.get(p + "HTTP_TIMEOUT_S") or 5.0),
            realm=realm or f"{prefix.lower()}-mcp",
        )


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _break_glass_from_env(env: Any, p: str, now: float) -> BreakGlassConfig | None:
    """Parse the break-glass settings. Unset = no break-glass. A malformed or
    over-long window is a ConfigError, never a silently wider one."""
    sha = (env.get(p + "BREAK_GLASS_SHA256") or "").strip().lower()
    until_raw = (env.get(p + "BREAK_GLASS_UNTIL") or "").strip()
    tier = (env.get(p + "BREAK_GLASS_TIER") or "").strip() or None
    owner = (env.get(p + "BREAK_GLASS_OWNER") or "").strip() or None
    if not sha:
        if until_raw:
            raise ConfigError(f"{p}BREAK_GLASS_UNTIL is set but {p}BREAK_GLASS_SHA256 is not")
        return None
    if not _HEX64.match(sha):
        raise ConfigError(f"{p}BREAK_GLASS_SHA256 must be 64 hex characters (the SHA-256 of the bearer)")
    if not until_raw:
        return BreakGlassConfig(sha256=sha, until=None, tier=tier, owner_sub=owner)
    if not UNTIL_PATTERN.match(until_raw):
        raise ConfigError(
            f"{p}BREAK_GLASS_UNTIL must be YYYY-MM-DDTHH:MM[:SS[.fff]] with Z or a timezone offset like +02:00: {until_raw!r}"
        )
    try:
        until_dt = datetime.fromisoformat(until_raw)
    except ValueError as exc:
        raise ConfigError(f"{p}BREAK_GLASS_UNTIL is not a valid datetime: {until_raw!r}") from exc
    until = until_dt.timestamp()
    if until > now + MAX_WINDOW_S:
        raise ConfigError(f"{p}BREAK_GLASS_UNTIL may be at most 24 hours ahead (got {until_raw!r})")
    if not tier:
        raise ConfigError(f"{p}BREAK_GLASS_TIER is required while {p}BREAK_GLASS_UNTIL is set")
    if not owner or not OWNER_PATTERN.match(owner):
        raise ConfigError(f"{p}BREAK_GLASS_OWNER must be the operator's 18-char Salesforce Id while {p}BREAK_GLASS_UNTIL is set")
    return BreakGlassConfig(sha256=sha, until=until, tier=tier, owner_sub=owner)
