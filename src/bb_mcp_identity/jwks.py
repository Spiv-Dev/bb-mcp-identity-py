"""The broker's public keys: pinned from config and/or fetched from the JWKS
URL, cached, refetched at most once per unknown ``kid``."""

from __future__ import annotations

import threading
import time
from typing import Any

import httpx
import jwt

ALG = "ES256"


class KeySet:
    def __init__(self, *, jwks_url: str, pinned: dict[str, Any] | None, ttl_s: int, timeout_s: float) -> None:
        self._url = jwks_url
        self._ttl = ttl_s
        self._timeout = timeout_s
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._last_error: str | None = None
        if pinned:
            self._absorb(pinned)
            self._fetched_at = time.time()

    def _absorb(self, jwks: dict[str, Any]) -> None:
        for k in jwks.get("keys", []):
            if not isinstance(k, dict) or k.get("kty") != "EC" or k.get("crv") != "P-256":
                continue
            if k.get("alg") not in (None, ALG) or "d" in k:
                continue
            kid = k.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            try:
                self._keys[kid] = jwt.PyJWK(k, algorithm=ALG).key
            except Exception:
                continue

    def fetch(self) -> bool:
        """Refresh from the JWKS URL. Returns True on success; never raises."""
        if not self._url:
            return False
        try:
            r = httpx.get(self._url, timeout=self._timeout, headers={"Accept": "application/json"})
            r.raise_for_status()
            jwks = r.json()
            with self._lock:
                self._absorb(jwks)
                self._fetched_at = time.time()
                self._last_error = None
            return True
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)[:200]
            return False

    def key_for(self, kid: str) -> Any | None:
        with self._lock:
            key = self._keys.get(kid)
            stale = time.time() - self._fetched_at > self._ttl
        if key is not None and not stale:
            return key
        # Unknown kid, or the cache aged out: one refetch, then whatever we have.
        self.fetch()
        with self._lock:
            return self._keys.get(kid)

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {"kids": sorted(self._keys), "fetched_at": int(self._fetched_at) or None, "last_error": self._last_error}
