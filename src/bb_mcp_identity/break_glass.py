"""Break-glass: one sealed, time-boxed, alerting operator bearer per server.

It exists so a lockout (broker down, Salesforce down, an entitlement mistake)
is never fixed by switching the identity mode off. It does not consult the
broker or the snapshot.

    sealed      the server holds only the SHA-256 of the bearer; the plaintext
                is minted once (``python -m bb_mcp_identity.break_glass <app>``)
                and kept offline.
    time-boxed  it works only while ``<PFX>_IDENTITY_BREAK_GLASS_UNTIL`` is in
                the future, and that value may be at most 24 hours ahead when
                the server starts. Unset or past = disarmed.
    alerting    every accepted use is logged at CRITICAL and passed to the
                server's ``on_break_glass`` hook (at most once a minute; every
                use is counted in ``health()``).

The principal acts as the operator named in ``BREAK_GLASS_OWNER`` (an 18-char
Salesforce Id) at ``BREAK_GLASS_TIER``, with ``kind="break_glass"``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("bb_mcp_identity.break_glass")

PREFIX = "bbg_"
MAX_WINDOW_S = 24 * 3600
ALERT_INTERVAL_S = 60.0

BreakGlassHook = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class BreakGlassConfig:
    sha256: str
    until: float | None  # unix seconds; None = configured but disarmed
    tier: str | None
    owner_sub: str | None

    def armed(self, now: float) -> bool:
        return self.until is not None and now < self.until


def mint(app: str) -> tuple[str, str]:
    """A new break-glass bearer and its SHA-256 hex. Keep the bearer offline."""
    token = f"{PREFIX}{app}_{secrets.token_urlsafe(32)}"
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


class BreakGlassOutcome:
    """The result of checking a ``bbg_`` bearer: ``ok`` or a stable deny reason."""

    __slots__ = ("ok", "reason")

    def __init__(self, ok: bool, reason: str) -> None:
        self.ok = ok
        self.reason = reason


class BreakGlass:
    def __init__(self, config: BreakGlassConfig | None, app: str, hook: BreakGlassHook | None = None) -> None:
        self.config = config
        self.app = app
        self.hook = hook
        self.uses = 0
        self.last_used: float | None = None
        self._last_alert = 0.0

    @staticmethod
    def is_candidate(bearer: str) -> bool:
        return bearer.startswith(PREFIX)

    def announce(self, now: float | None = None) -> None:
        """Log the armed state once at start, so an armed server is never quiet about it."""
        if self.config is None:
            return
        now = time.time() if now is None else now
        if self.config.armed(now):
            log.critical(
                "identity break-glass ARMED for app %s until %s (tier %s, owner %s)",
                self.app,
                _iso(self.config.until),
                self.config.tier,
                self.config.owner_sub,
            )
        else:
            log.info("identity break-glass configured for app %s, not armed", self.app)

    def check(self, bearer: str, now: float) -> BreakGlassOutcome:
        if self.config is None:
            log.warning("identity break-glass bearer presented but none is configured (app %s)", self.app)
            return BreakGlassOutcome(False, "break_glass_not_configured")
        presented = hashlib.sha256(bearer.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(presented, self.config.sha256):
            log.error("identity break-glass bearer REJECTED: no match (app %s)", self.app)
            return BreakGlassOutcome(False, "break_glass_mismatch")
        if not self.config.armed(now):
            log.error("identity break-glass bearer REJECTED: not armed (app %s)", self.app)
            return BreakGlassOutcome(False, "break_glass_not_armed")
        self.uses += 1
        self.last_used = now
        if now - self._last_alert >= ALERT_INTERVAL_S:
            self._last_alert = now
            event = {
                "event": "identity.break_glass_used",
                "app": self.app,
                "owner_sub": self.config.owner_sub,
                "tier": self.config.tier,
                "until": _iso(self.config.until),
                "uses": self.uses,
                "at": _iso(now),
            }
            log.critical("identity BREAK-GLASS bearer used: %s", event)
            if self.hook is not None:
                try:
                    self.hook(event)
                except Exception:  # an alert hook must never break the request
                    log.exception("identity break-glass alert hook failed")
        return BreakGlassOutcome(True, "ok")

    def health(self, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        cfg = self.config
        return {
            "configured": cfg is not None,
            "armed": bool(cfg and cfg.armed(now)),
            "until": _iso(cfg.until) if cfg and cfg.until is not None else None,
            "uses": self.uses,
            "last_used": _iso(self.last_used) if self.last_used is not None else None,
        }


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or not args[0]:
        print("usage: python -m bb_mcp_identity.break_glass <app-key>", file=sys.stderr)
        return 2
    token, digest = mint(args[0])
    print(f"bearer (store offline, shown once): {token}")
    print(f"<PFX>_IDENTITY_BREAK_GLASS_SHA256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
