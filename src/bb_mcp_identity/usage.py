"""Usage ledger: one JSON line per MCP tool call, for the fleet usage feed.

    from bb_mcp_identity.usage import UsageLedger

    usage = UsageLedger.from_env("DEV", server="development", version=__version__)
    usage.write_catalog([{"name": "dev_ping", "kind": "read", "domain": "meta"}])
    ...
    usage.record(tool="dev_ping", outcome="ok", duration_ms=12, user="mitchell", user_kind="user")

Each server appends events to ``<dir>/usage-YYYY-MM-DD.jsonl`` (UTC day, mode
0600). A shipper on the VM reads the files and loads them into the fleet usage
store; nothing here talks to the network. ``<PREFIX>_USAGE_DIR`` unset means the
ledger does nothing.

What an event holds is fixed by ``spec/usage_event_v1.json``: call metadata
(tool, person, outcome, timing, sizes, argument NAMES) and, optionally, the
person's question after :func:`redact_question`. Argument values and results are
never accepted. ``record`` never raises: a bad field is dropped and counted, a
write failure is counted, and the tool call carries on.

This module imports nothing from the auth code.
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import threading
import time
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

log = logging.getLogger("bb_mcp_identity.usage")

SCHEMA_VERSION = 1
RETENTION_DAYS = 14
QUESTION_LIMIT = 500

KINDS = ("read", "write", "admin")
USER_KINDS = ("user", "service", "break_glass", "legacy", "system", "unknown")
OUTCOMES = ("ok", "error", "denied")
WRITE_MODES = ("preview", "apply", "n/a")

# Field order of the JSON line (the shipper does not depend on it; it keeps lines diffable).
FIELD_ORDER = (
    "v",
    "id",
    "ts",
    "server",
    "server_version",
    "tool",
    "kind",
    "user",
    "user_kind",
    "tier",
    "client",
    "outcome",
    "error_code",
    "duration_ms",
    "response_bytes",
    "arg_keys",
    "write_mode",
    "via_tool",
    "correlation_id",
    "parent_correlation_id",
    "question",
)

_MAX = {
    "server": 64,
    "server_version": 64,
    "tool": 128,
    "user": 64,
    "tier": 32,
    "client": 200,
    "error_code": 64,
    "via_tool": 128,
    "correlation_id": 128,
    "parent_correlation_id": 128,
}
_MAX_ARG_KEYS = 64
_MAX_ARG_KEY_LEN = 64

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9._-]")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_CONTROL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FILE_RE = re.compile(r"^usage-(\d{4}-\d{2}-\d{2})\.jsonl$")


# --- redaction ------------------------------------------------------------------------------
#
# The same patterns, in the same order, live in bb-mcp-identity-ts (src/usage.ts) and both are
# held to spec/redaction_fixtures_v1.json. Character classes are spelt out ([0-9], [ \t]) rather
# than \d / \s so Python and JavaScript match exactly the same text.

_WS = "[ \\t\\r\\n\\f\\v\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff]"
_SP = "[ \\t\\u00a0]"  # a space inside a number ("R 12 500")
_NUM = f"[0-9](?:[0-9,.]|{_SP}(?=[0-9]))*"
_SCALE = "(?:k|m|bn|million|thousand|mil)"

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:https?://|www\.)[^ \t\r\n]+", re.ASCII | re.IGNORECASE), "[url]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}", re.ASCII), "[email]"),
    # Phones: South African (+27 / 0xx) and other international (+cc) numbers.
    (re.compile(r"(?:\+27|\b0)[ -]?\(?[0-9]{2}\)?[ -]?[0-9]{3}[ -]?[0-9]{4}\b", re.ASCII), "[phone]"),
    (re.compile(r"\+[0-9]{1,3}(?:[ -]?[0-9]){7,12}\b", re.ASCII), "[phone]"),
    # Card-like runs (13-19 digits, optional single separators), then any 9+ digit run (SA ID,
    # account numbers).
    (re.compile(r"\b[0-9](?:[ -]?[0-9]){12,18}\b", re.ASCII), "[number]"),
    (re.compile(r"\b[0-9]{9,}\b", re.ASCII), "[number]"),
    # Amounts: a currency marker before or after the figure, or a bare figure with a scale.
    (
        re.compile(
            rf"(?:\b(?:R|ZAR|USD|EUR|GBP){_SP}?|[$€£]{_SP}?){_NUM}(?:{_SP}?{_SCALE}\b)?",
            re.ASCII | re.IGNORECASE,
        ),
        "[amount]",
    ),
    (re.compile(rf"\b{_NUM}{_SP}?(?:ZAR|USD|EUR|GBP|rand)\b", re.ASCII | re.IGNORECASE), "[amount]"),
    (re.compile(rf"\b[0-9]+(?:[.,][0-9]+)?{_SP}?(?:k|m|bn)\b", re.ASCII | re.IGNORECASE), "[amount]"),
)

# Salesforce Ids: 15 or 18 letters/digits with at least one digit and one letter, so ordinary
# words ("Implementations") survive.
_SFID_RE = re.compile(r"\b[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?\b", re.ASCII)
_HAS_DIGIT = re.compile(r"[0-9]")
_HAS_LETTER = re.compile(r"[A-Za-z]")
_WS_RE = re.compile(_WS + "+")


def _sfid(m: re.Match[str]) -> str:
    tok = m.group(0)
    return "[id]" if _HAS_DIGIT.search(tok) and _HAS_LETTER.search(tok) else tok


def _clean(s: str) -> str:
    """Replace lone surrogates (Postgres rejects them) and drop control characters."""
    return _CONTROL_RE.sub("", _SURROGATE_RE.sub("�", s))


def redact_question(text: object, limit: int = QUESTION_LIMIT) -> str | None:
    """Strip contact details, numbers, Ids and amounts from a question, then cut it to ``limit``.

    Redaction runs before truncation, so a cut can never leave half an address behind. Names
    are NOT removed (they cannot be found reliably); the store keeps questions separately and
    for 90 days for that reason. Returns None for a blank or non-string question.
    """
    if not isinstance(text, str):
        return None
    s = _clean(text)
    for pattern, placeholder in _REDACTIONS:
        s = pattern.sub(placeholder, s)
    s = _SFID_RE.sub(_sfid, s)
    s = _WS_RE.sub(" ", s).strip(" ")
    if not s:
        return None
    return s[:limit].rstrip(" ") if len(s) > limit else s


def user_slug(username: object) -> str | None:
    """The fleet's person key: the lowercase local part of a username or email."""
    if not isinstance(username, str):
        return None
    local = username.strip().lower().split("@", 1)[0]
    slug = _SLUG_STRIP_RE.sub("", local)[: _MAX["user"]]
    return slug or None


# --- the ledger -----------------------------------------------------------------------------


class UsageLedger:
    """Append-only JSONL writer. Thread-safe; never raises from ``record``."""

    def __init__(
        self,
        directory: str | os.PathLike[str] | None,
        *,
        server: str,
        version: str = "",
        retention_days: int = RETENTION_DAYS,
    ) -> None:
        self.dir = Path(directory) if directory else None
        self.server = _short(server, "server") or "unknown"
        self.version = _short(version, "server_version") or ""
        self.retention_days = max(1, int(retention_days))
        self._lock = threading.Lock()
        self._pruned_day: str | None = None
        self.written = 0
        self.dropped_fields = 0
        self.write_errors = 0
        self.last_error: str | None = None

    @classmethod
    def from_env(cls, prefix: str, *, server: str, version: str = "") -> UsageLedger:
        return cls(os.environ.get(f"{prefix}_USAGE_DIR") or None, server=server, version=version)

    @property
    def enabled(self) -> bool:
        return self.dir is not None

    def stats(self) -> dict[str, Any]:
        """Counters for a server's health / selftest tool."""
        return {
            "enabled": self.enabled,
            "dir": str(self.dir) if self.dir else None,
            "written": self.written,
            "dropped_fields": self.dropped_fields,
            "write_errors": self.write_errors,
            "last_error": self.last_error,
        }

    def build_event(self, **fields: Any) -> dict[str, Any]:
        """The event ``record`` would write (validated, unknown fields dropped). Never raises."""
        now = fields.pop("ts", None)
        ts = now if isinstance(now, datetime) else datetime.now(UTC)
        ev: dict[str, Any] = {
            "v": SCHEMA_VERSION,
            "id": uuid.uuid4().hex,
            "ts": ts.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "server": self.server,
            "server_version": self.version,
        }
        unknown = set(fields) - set(FIELD_ORDER)
        self.dropped_fields += len(unknown)

        tool = _short(fields.get("tool"), "tool")
        ev["tool"] = tool or "unknown"
        ev["kind"] = self._enum(fields.get("kind", "read"), KINDS, "read")
        ev["user"] = user_slug(fields.get("user"))
        ev["user_kind"] = self._enum(fields.get("user_kind", "unknown"), USER_KINDS, "unknown")
        ev["tier"] = _short(fields.get("tier"), "tier")
        ev["client"] = _short(fields.get("client"), "client")
        ev["outcome"] = self._enum(fields.get("outcome"), OUTCOMES, "error")
        ev["error_code"] = _short(fields.get("error_code"), "error_code")
        ev["duration_ms"] = self._count(fields.get("duration_ms"), default=0)
        ev["response_bytes"] = self._count(fields.get("response_bytes"), default=None)
        ev["arg_keys"] = self._arg_keys(fields.get("arg_keys"))
        ev["write_mode"] = self._enum(fields.get("write_mode", "n/a"), WRITE_MODES, "n/a")
        ev["via_tool"] = _short(fields.get("via_tool"), "via_tool")
        ev["correlation_id"] = _short(fields.get("correlation_id"), "correlation_id")
        ev["parent_correlation_id"] = _short(fields.get("parent_correlation_id"), "parent_correlation_id")
        ev["question"] = redact_question(fields.get("question"))
        return {k: ev[k] for k in FIELD_ORDER}

    def record(self, **fields: Any) -> bool:
        """Append one event. Returns True if it was written; never raises."""
        if self.dir is None:
            return False
        try:
            ev = self.build_event(**fields)
            line = (json.dumps(ev, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            day = ev["ts"][:10]
            with self._lock:
                self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(self.dir / f"usage-{day}.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, line)  # one write per line: a reader never sees half of one
                finally:
                    os.close(fd)
                self.written += 1
                if self._pruned_day != day:
                    self._pruned_day = day
                    self._prune(day)
            return True
        except Exception as exc:  # the tool call must never fail because of usage tracking
            self.write_errors += 1
            self.last_error = type(exc).__name__
            log.debug("usage ledger write failed: %s", type(exc).__name__)
            return False

    def write_catalog(self, tools: Iterable[Mapping[str, Any]]) -> bool:
        """Write ``tools.json`` (the server's registered tools) atomically. Never raises."""
        if self.dir is None:
            return False
        try:
            rows: list[dict[str, Any]] = []
            for t in tools:
                name = _short(t.get("name"), "tool")
                if not name:
                    continue
                rows.append(
                    {
                        "name": name,
                        "kind": self._enum(t.get("kind", "read"), KINDS, "read"),
                        "domain": _short(t.get("domain"), "tool"),
                    }
                )
            doc = {
                "v": SCHEMA_VERSION,
                "server": self.server,
                "server_version": self.version,
                "generated_at": datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z"),
                "tools": sorted(rows, key=lambda r: r["name"]),
            }
            self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = self.dir / f".tools.json.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(fd, json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(tmp, self.dir / "tools.json")
            return True
        except Exception as exc:
            self.write_errors += 1
            self.last_error = type(exc).__name__
            return False

    # -- helpers --

    def _prune(self, today: str) -> None:
        assert self.dir is not None
        try:
            cutoff = (datetime.strptime(today, "%Y-%m-%d") - timedelta(days=self.retention_days)).strftime("%Y-%m-%d")
            for p in self.dir.iterdir():
                m = _FILE_RE.match(p.name)
                if m and m.group(1) < cutoff:
                    p.unlink(missing_ok=True)
        except OSError as exc:
            self.last_error = type(exc).__name__

    def _enum(self, value: object, allowed: tuple[str, ...], default: str) -> str:
        if value in allowed:
            return str(value)
        if value is not None:
            self.dropped_fields += 1
        return default

    def _count(self, value: object, *, default: int | None) -> int | None:
        if isinstance(value, bool) or value is None:
            return default
        if isinstance(value, int | float) and math.isfinite(value) and value >= 0:
            return math.floor(value + 0.5)  # half-up, as JavaScript Math.round
        self.dropped_fields += 1
        return default

    def _arg_keys(self, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, Mapping):  # tolerate a kwargs dict: keep the names, never the values
            value = list(value.keys())
        if isinstance(value, str) or not isinstance(value, Iterable):
            self.dropped_fields += 1
            return []
        keys: set[str] = set()
        for k in value:
            if isinstance(k, str) and k and not k.startswith("_") and len(k) <= _MAX_ARG_KEY_LEN and _NAME_RE.match(k):
                keys.add(k)
        return sorted(keys)[:_MAX_ARG_KEYS]


def _short(value: object, field: str) -> str | None:
    if not isinstance(value, str):
        return None
    s = _CONTROL_RE.sub("", _SURROGATE_RE.sub("�", value)).strip()
    return s[: _MAX[field]] or None


def elapsed_ms(start: float) -> int:
    """Milliseconds since a ``time.perf_counter()`` start."""
    return math.floor((time.perf_counter() - start) * 1000 + 0.5)
