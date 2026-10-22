"""Service principals: the non-human callers that keep a static bearer.

File format, one per line (mode 600, never committed):

    svc-<name>:<tier>:<owner 18-char Salesforce id>:<expires ISO date>:<token>

A service principal is honoured only while its owner is present and active
in the broker snapshot and its expiry is in the future.
"""

from __future__ import annotations

import hmac
import logging
import os
from dataclasses import dataclass
from datetime import UTC, date, datetime

from .snapshot import SnapshotStore

log = logging.getLogger("bb_mcp_identity.service_principals")


@dataclass(frozen=True)
class ServicePrincipal:
    name: str
    tier: str
    owner_sub: str
    expires: date
    token: str


def parse_lines(text: str) -> list[ServicePrincipal]:
    out: list[ServicePrincipal] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 4)
        if len(parts) != 5:
            raise ValueError("service principal line must have 5 colon-separated fields")
        name, tier, owner, expires, token = (p.strip() for p in parts)
        if not name.startswith("svc-") or not tier or len(owner) != 18 or len(token) < 32:
            raise ValueError(f"malformed service principal line for {name!r}")
        out.append(ServicePrincipal(name=name, tier=tier, owner_sub=owner, expires=date.fromisoformat(expires), token=token))
    return out


class ServicePrincipals:
    def __init__(self, principals: list[ServicePrincipal]) -> None:
        self._principals = principals

    @classmethod
    def from_file(cls, path: str | None) -> ServicePrincipals:
        if not path or not os.path.exists(path):
            return cls([])
        with open(path, encoding="utf-8") as f:
            return cls(parse_lines(f.read()))

    def match(self, bearer: str) -> ServicePrincipal | None:
        for p in self._principals:
            if hmac.compare_digest(p.token.encode(), bearer.encode()):
                return p
        return None

    @staticmethod
    def usable(p: ServicePrincipal, snapshot: SnapshotStore, today: date | None = None) -> tuple[bool, str]:
        today = today or datetime.now(UTC).date()
        if p.expires < today:
            return False, "expired"
        if not snapshot.is_fresh():
            return False, "snapshot_stale"
        owner = snapshot.entry(p.owner_sub)
        if owner is None:
            return False, "owner_unknown"
        if not owner.active:
            return False, f"owner_{owner.status}"
        return True, "ok"

    def __len__(self) -> int:
        return len(self._principals)
