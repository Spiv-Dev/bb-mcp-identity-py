"""Verify a bearer against the broker: signature (ES256, pinned or fetched
keys), issuer, audience, expiry, then the snapshot (active, entitled,
not_before, fresh). Every failure is a ``Deny`` with a stable reason."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import jwt

from .config import IdentityConfig
from .jwks import ALG, KeySet
from .service_principals import ServicePrincipal, ServicePrincipals
from .snapshot import SnapshotStore

log = logging.getLogger("bb_mcp_identity.verifier")


@dataclass(frozen=True)
class Principal:
    """A verified caller. ``sub`` is the 18-char Salesforce User Id."""

    sub: str
    username: str
    app: str
    tier: str
    scopes: tuple[str, ...]
    client_id: str
    auth_time: int
    jti: str
    exp: int
    kind: str = "user"  # user | service

    @property
    def scope(self) -> str:
        return " ".join(self.scopes)


class Deny(Exception):
    """The bearer must be refused. ``reason`` is stable and safe to log; ``ours``
    says whether the token was issued by our broker at all (an enabled-mode
    server lets a non-broker token fall through to its legacy validator)."""

    def __init__(self, reason: str, *, ours: bool = True) -> None:
        super().__init__(reason)
        self.reason = reason
        self.ours = ours


class Verifier:
    def __init__(self, config: IdentityConfig) -> None:
        self.config = config
        self.keys = KeySet(jwks_url=config.jwks_url, pinned=config.pinned_jwks, ttl_s=config.jwks_ttl_s, timeout_s=config.http_timeout_s)
        self.snapshot = SnapshotStore(
            url=config.snapshot_url,
            verifier_token=config.verifier_token,
            app=config.app,
            cache_path=config.snapshot_cache_path,
            poll_interval_s=config.poll_interval_s,
            timeout_s=config.http_timeout_s,
        )
        self.service_principals = ServicePrincipals.from_file(config.service_principals_path)

    def start(self) -> None:
        """Fetch keys and the snapshot once, then keep polling in the background."""
        if not self.config.enabled:
            return
        self.keys.fetch()
        self.snapshot.start()

    def stop(self) -> None:
        self.snapshot.stop()

    # ── tokens ──────────────────────────────────────────────────────────

    def verify(self, bearer: str, now: float | None = None) -> Principal:
        if not self.config.enabled:
            raise Deny("identity_off", ours=False)
        now = time.time() if now is None else now
        svc = self.service_principals.match(bearer) if bearer.startswith("bbs_") or len(self.service_principals) else None
        if svc is not None:
            return self._service(svc)
        try:
            header = jwt.get_unverified_header(bearer)
        except jwt.PyJWTError:
            raise Deny("not_a_jwt", ours=False) from None
        if header.get("alg") != ALG:
            # Not ours (or an algorithm-confusion attempt). Never verify anything but ES256.
            raise Deny("wrong_alg", ours=False)
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise Deny("no_kid", ours=False)
        key = self.keys.key_for(kid)
        if key is None:
            raise Deny("unknown_kid")
        try:
            claims = jwt.decode(
                bearer,
                key=key,
                algorithms=[ALG],
                audience=self.config.resource,
                issuer=self.config.issuer,
                leeway=self.config.leeway_s,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError:
            raise Deny("expired") from None
        except jwt.InvalidAudienceError:
            raise Deny("wrong_audience") from None
        except jwt.InvalidIssuerError:
            raise Deny("wrong_issuer") from None
        except jwt.PyJWTError as exc:
            raise Deny(f"invalid_token:{type(exc).__name__}") from None

        sub = str(claims.get("sub", ""))
        auth_time = int(claims.get("auth_time") or 0)
        if len(sub) != 18 or not auth_time:
            raise Deny("malformed_claims")
        if claims.get("app") not in (None, self.config.app):
            raise Deny("wrong_app")

        # The snapshot decides. It is newer than the token.
        if not self.snapshot.is_fresh(now):
            raise Deny("snapshot_stale" if self.snapshot.version is not None else "no_snapshot")
        entry = self.snapshot.entry(sub)
        if entry is None:
            raise Deny("unknown_subject")
        if not entry.active:
            raise Deny(f"subject_{entry.status}")
        if auth_time < entry.not_before:
            raise Deny("not_before")
        if not entry.tier:
            raise Deny("not_entitled")
        return Principal(
            sub=sub,
            username=str(claims.get("preferred_username") or ""),
            app=self.config.app,
            tier=entry.tier,
            scopes=tuple(entry.scopes),
            client_id=str(claims.get("client_id") or ""),
            auth_time=auth_time,
            jti=str(claims.get("jti") or ""),
            exp=int(claims.get("exp") or 0),
        )

    def _service(self, svc: ServicePrincipal) -> Principal:
        ok, reason = ServicePrincipals.usable(svc, self.snapshot)
        if not ok:
            raise Deny(f"service_{reason}")
        return Principal(
            sub=svc.owner_sub,
            username=svc.name,
            app=self.config.app,
            tier=svc.tier,
            scopes=(),
            client_id=svc.name,
            auth_time=0,
            jti="",
            exp=0,
            kind="service",
        )

    # ── health ──────────────────────────────────────────────────────────

    def health(self) -> dict[str, Any]:
        return {
            "mode": self.config.mode,
            "issuer": self.config.issuer,
            "resource": self.config.resource,
            "keys": self.keys.health(),
            "snapshot": self.snapshot.health(),
            "service_principals": len(self.service_principals),
        }
