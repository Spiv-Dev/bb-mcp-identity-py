"""The broker's entitlement snapshot for this app: polled, cached on disk,
and consulted on every request. See docs/VERIFIER_PROTOCOL.md section 4 in
the bb-identity repo for the contract."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger("bb_mcp_identity.snapshot")


@dataclass(frozen=True)
class SubjectEntry:
    status: str
    active: bool
    not_before: int
    tier: str | None
    scope: str | None

    @property
    def scopes(self) -> list[str]:
        return (self.scope or "").split()


class SnapshotStore:
    def __init__(
        self,
        *,
        url: str,
        verifier_token: str | None,
        app: str,
        cache_path: str | None,
        poll_interval_s: int,
        timeout_s: float,
    ) -> None:
        self._url = url
        self._token = verifier_token
        self._app = app
        self._cache_path = cache_path
        self._interval = poll_interval_s
        self._timeout = timeout_s
        self._lock = threading.Lock()
        self._snapshot: dict[str, Any] | None = None
        self._etag: str | None = None
        self._loaded_at: float = 0.0
        self._last_error: str | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        if cache_path and os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as f:
                    self._accept(json.load(f), persist=False)
                log.info("identity snapshot restored from %s (version %s)", cache_path, self.version)
            except Exception as exc:
                log.warning("identity snapshot cache unreadable: %s", exc)

    # ── state ───────────────────────────────────────────────────────────

    def _accept(self, body: dict[str, Any], *, persist: bool) -> None:
        if not isinstance(body, dict) or body.get("app") != self._app or not isinstance(body.get("subjects"), dict):
            raise ValueError("snapshot is not for this app")
        with self._lock:
            self._snapshot = body
            self._etag = f'"{body.get("version")}"'
            self._loaded_at = time.time()
            self._last_error = None
        if persist and self._cache_path:
            tmp = f"{self._cache_path}.tmp"
            try:
                os.makedirs(os.path.dirname(self._cache_path) or ".", exist_ok=True)
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(body, f)
                os.replace(tmp, self._cache_path)
                try:
                    os.chmod(self._cache_path, 0o600)
                except OSError:
                    pass
            except OSError as exc:
                log.warning("could not persist identity snapshot: %s", exc)

    @property
    def version(self) -> int | None:
        with self._lock:
            return None if self._snapshot is None else int(self._snapshot.get("version", 0))

    def generated_at_ms(self) -> int | None:
        with self._lock:
            return None if self._snapshot is None else int(self._snapshot.get("generated_at", 0))

    def stale_after_s(self) -> int:
        with self._lock:
            return int((self._snapshot or {}).get("stale_after_s", 1200))

    def is_fresh(self, now: float | None = None) -> bool:
        gen = self.generated_at_ms()
        if gen is None:
            return False
        now_ms = (now if now is not None else time.time()) * 1000
        return now_ms - gen <= self.stale_after_s() * 1000

    def entry(self, sub: str) -> SubjectEntry | None:
        with self._lock:
            if self._snapshot is None:
                return None
            raw = self._snapshot["subjects"].get(sub)
        if not isinstance(raw, dict):
            return None
        return SubjectEntry(
            status=str(raw.get("status", "unknown")),
            active=bool(raw.get("active", False)),
            not_before=int(raw.get("not_before", 0)),
            tier=raw.get("tier"),
            scope=raw.get("scope"),
        )

    # ── fetching ────────────────────────────────────────────────────────

    def fetch(self) -> bool:
        """One poll. Returns True when a usable snapshot is loaded afterwards; never raises."""
        if not self._url or not self._token:
            with self._lock:
                self._last_error = "snapshot url or verifier token not configured"
            return self._snapshot is not None
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        with self._lock:
            etag = self._etag if self._snapshot is not None else None
        if etag:
            headers["If-None-Match"] = etag
        try:
            r = httpx.get(self._url, headers=headers, timeout=self._timeout)
            if r.status_code == 304:
                with self._lock:
                    self._last_error = None
                return True
            r.raise_for_status()
            self._accept(r.json(), persist=True)
            return True
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)[:200]
            log.warning("identity snapshot poll failed: %s", exc)
            return self._snapshot is not None

    def start(self) -> None:
        if self._thread is not None:
            return
        self.fetch()

        def loop() -> None:
            while not self._stop.wait(self._interval):
                self.fetch()

        self._thread = threading.Thread(target=loop, name="bb-identity-snapshot", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread = None

    def health(self) -> dict[str, Any]:
        gen = self.generated_at_ms()
        return {
            "version": self.version,
            "generated_at": None if gen is None else gen // 1000,
            "age_s": None if gen is None else max(0, int(time.time() - gen / 1000)),
            "fresh": self.is_fresh(),
            "stale_after_s": self.stale_after_s(),
            "last_error": self._last_error,
            "subjects": None if self._snapshot is None else len(self._snapshot["subjects"]),
        }
