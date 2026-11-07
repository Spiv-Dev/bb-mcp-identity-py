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
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
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

# Argument names are identifiers; a key with 5+ digits is more likely a value than a name.
_ARG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_ARG_DIGITS_RE = re.compile(r"[0-9]")
_TOOL_STRIP_RE = re.compile(r"[^A-Za-z0-9_.:-]")
_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_TIER_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
_VERSION_STRIP_RE = re.compile(r"[^A-Za-z0-9_.+-]")
MAX_COUNT = 2**53 - 1  # the largest integer JavaScript (and so the TS twin) keeps exactly
MAX_DURATION_MS = 2**31 - 1  # the store's integer column
_SLUG_STRIP_RE = re.compile(r"[^a-z0-9._-]")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_CONTROL_RE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_FILE_RE = re.compile(r"^usage-(\d{4}-\d{2}-\d{2})\.jsonl$")


# --- redaction ------------------------------------------------------------------------------
#
# The same steps and patterns, in the same order, live in bb-mcp-identity-ts (src/usage.ts) and
# both are held to spec/redaction_fixtures_v1.json. Character classes are spelt out ([0-9],
# [ \t]) rather than \d / \s so Python and JavaScript match exactly the same text, and every
# pattern starts only at a token boundary so a long input cannot make it quadratic.
#
# Steps: drop invisible characters, turn every kind of space into ' ', cut the input to
# PRE_LIMIT characters at a space (so no token is split), redact, then cut to the limit.

PRE_LIMIT = 1200

_WS = "[ \\t\\r\\n\\f\\v\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]"
_WS_RE = re.compile(_WS + "+")
_INVISIBLE_RE = re.compile("[\\u00ad\\u200b-\\u200d\\u2060\\ufeff]")
_SP = "[ \\t]"
_NUM = f"[0-9](?:[0-9]|[,.][0-9]|{_SP}(?=[0-9]))*"
_SCALE = "(?:k|mn|mm|m|bn|million|billion|thousand|mil|miljoen)"
_BARE_SCALE = "(?:k|mn|mm|bn|million|billion|miljoen)"
_CUR = "(?:ZAR|USD|EUR|GBP|rand|dollars?|euros?)"
_NOT_IN_NUMBER = "(?<![0-9A-Za-z,.])"
_EMAIL_CH = '[^ @<>()\\[\\],;:"]'

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,15}://[^ ]+|\bwww\.[^ ]+", re.ASCII | re.IGNORECASE), "[url]"),
    (
        re.compile(f'(?<![^ <>()\\[\\],;:"\']){_EMAIL_CH}+@{_EMAIL_CH}+\\.[^ @<>()\\[\\],;:".]{{2,}}'),
        "[email]",
    ),
    (re.compile(r"(?<![^ (<\[\"'])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\.[A-Za-z]{2,}/[^ ]*", re.ASCII), "[url]"),
    # Long opaque tokens (API keys, session tokens): 24+ letters/digits/-/_ with both a digit and a letter.
    (
        re.compile(
            r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[0-9])(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9_-]{24,}(?![A-Za-z0-9_-])",
            re.ASCII,
        ),
        "[secret]",
    ),
    # Amounts: a currency marker before or after the figure, a scaled figure, or grouped thousands.
    (
        re.compile(
            f"(?:\\b(?:R|ZAR|USD|EUR|GBP)|[$\\u20ac\\u00a3]){_SP}?{_NUM}(?:{_SP}?{_SCALE})?(?![0-9A-Za-z])",
            re.ASCII | re.IGNORECASE,
        ),
        "[amount]",
    ),
    (
        re.compile(f"{_NOT_IN_NUMBER}{_NUM}{_SP}?(?:{_SCALE}{_SP}?)?{_CUR}\\b", re.ASCII | re.IGNORECASE),
        "[amount]",
    ),
    (
        re.compile(f"{_NOT_IN_NUMBER}[0-9]+(?:[.,][0-9]+)?{_SP}?{_BARE_SCALE}\\b", re.ASCII | re.IGNORECASE),
        "[amount]",
    ),
    (re.compile(f"{_NOT_IN_NUMBER}[0-9]{{1,3}}(?:,[0-9]{{3}})+(?:\\.[0-9]+)?(?![0-9])", re.ASCII), "[amount]"),
)

# Phones, ID and account numbers, cards: a run of 9+ digits with up to three separators
# (space . - ( )) between them. Dates and years inside the run do not count towards the 9.
_DIGIT_RUN_RE = re.compile(r"(?<![0-9A-Za-z])\+?\(?[0-9](?:[ .()-]{0,3}[0-9]){8,}", re.ASCII)
_ISO_DATE_RE = re.compile(r"(?:19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}", re.ASCII)
_YEAR_RE = re.compile(r"(?:19|20)[0-9]{2}", re.ASCII)
_NON_DIGITS_RE = re.compile(r"[^0-9]+", re.ASCII)
_DIGIT_RE = re.compile(r"[0-9]", re.ASCII)
# Letter-prefixed document numbers (passports, permits): 1-2 letters then 6-9 digits.
_DOCNUM_RE = re.compile(r"\b[A-Za-z]{1,2}[0-9]{6,9}\b", re.ASCII)
# Salesforce Ids: 15 or 18 letters/digits with at least three digits and a letter.
_SFID_RE = re.compile(r"\b[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?\b", re.ASCII)
_LETTER_RE = re.compile(r"[A-Za-z]", re.ASCII)


def _digit_run(m: re.Match[str]) -> str:
    tok = m.group(0)
    groups = [g for g in _NON_DIGITS_RE.split(tok) if g]
    if groups and all(_YEAR_RE.fullmatch(g) for g in groups):
        return tok  # a list of years ("2024 2025 2026")
    if len(_DIGIT_RE.findall(_ISO_DATE_RE.sub("", tok))) < 9:
        return tok  # dates and a time, not a number
    return "[phone]" if tok[0] in "+0(" else "[number]"


def _sfid(m: re.Match[str]) -> str:
    tok = m.group(0)
    return "[id]" if len(_DIGIT_RE.findall(tok)) >= 3 and _LETTER_RE.search(tok) else tok


def _clean(s: str) -> str:
    """Replace lone surrogates (Postgres rejects them) and drop control characters."""
    return _CONTROL_RE.sub("", _SURROGATE_RE.sub("�", s))


def _trim(s: str) -> str:
    """Collapse every kind of space to one ' ' and trim (the same in Python and JavaScript)."""
    return _WS_RE.sub(" ", _INVISIBLE_RE.sub("", s)).strip(" ")


def redact_question(text: object, limit: int = QUESTION_LIMIT) -> str | None:
    """Strip contact details, numbers, Ids, links, tokens and amounts from a question, then cut it.

    Names are NOT removed (they cannot be found reliably); the store keeps questions separately
    and for 90 days for that reason. Returns None for a blank or non-string question.
    """
    if not isinstance(text, str):
        return None
    s = _trim(_clean(text))
    if len(s) > PRE_LIMIT:
        cut = s[:PRE_LIMIT]
        space = cut.rfind(" ")
        s = cut[:space] if space > PRE_LIMIT // 2 else cut
    for pattern, placeholder in _REDACTIONS:
        s = pattern.sub(placeholder, s)
    s = _DIGIT_RUN_RE.sub(_digit_run, s)
    s = _DOCNUM_RE.sub("[id]", s)
    s = _SFID_RE.sub(_sfid, s)
    s = _trim(s)
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


# --- mapping a Python tool call's envelope -------------------------------------------------

# Envelope error codes that mean "not allowed" (a permission or mode refusal: demand the caller
# could not meet), as the fleet's Python servers spell them. Anything else with ok=false is an
# error. A server can pass its own set to ``record_call``.
DENIED_ERRORS = frozenset(
    {
        "forbidden",
        "unauthorized",
        "not_authorized",
        "insufficient_scope",
        "permission_denied",
        "server_in_read_only_mode",
        "read_only",
        "rbac_denied",
    }
)
RATE_LIMIT_ERRORS = frozenset({"rate_limited", "rate_limit", "too_many_requests", "RATE_LIMITED"})
META_ARGS = ("user_question", "user_id", "_user_question", "_user_id")

_CURRENT_TOOL: ContextVar[str | None] = ContextVar("bb_usage_current_tool", default=None)


@contextmanager
def tool_scope(tool: str) -> Iterator[str | None]:
    """Mark ``tool`` as running; yields the tool that called it in-process (None at the top)."""
    parent = _CURRENT_TOOL.get()
    token = _CURRENT_TOOL.set(tool)
    try:
        yield parent
    finally:
        _CURRENT_TOOL.reset(token)


def envelope_outcome(result: object, exc: BaseException | None = None, *, denied: frozenset[str] = DENIED_ERRORS) -> tuple[str, str | None]:
    """(outcome, error_code) for a tool's return value or exception."""
    if exc is not None:
        return "error", type(exc).__name__
    if isinstance(result, Mapping) and result.get("ok") is False:
        raw = result.get("error") or result.get("error_code") or result.get("code") or "error"
        code = raw if isinstance(raw, str) else type(raw).__name__
        if code in RATE_LIMIT_ERRORS:
            return "error", "RATE_LIMITED"
        return ("denied" if code in denied else "error"), code
    return "ok", None


def response_size(result: object) -> int | None:
    """UTF-8 size of the result as JSON (what the client receives, near enough); None if unknown."""
    if result is None:
        return None
    try:
        return len(json.dumps(result, default=str, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    except (TypeError, ValueError, RecursionError):
        return None


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
        self.server = _name(server, "server") or "unknown"
        self.version = (_VERSION_STRIP_RE.sub("", version) if isinstance(version, str) else "")[: _MAX["server_version"]]
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

        ev["tool"] = _name(fields.get("tool"), "tool") or "unknown"
        ev["kind"] = self._enum(fields.get("kind", "read"), KINDS, "read")
        ev["user"] = user_slug(fields.get("user"))
        ev["user_kind"] = self._enum(fields.get("user_kind", "unknown"), USER_KINDS, "unknown")
        tier = fields.get("tier")
        ev["tier"] = tier.lower() if isinstance(tier, str) and _TIER_RE.match(tier.lower()) else None
        ev["client"] = redact_question(fields.get("client"), _MAX["client"])
        ev["outcome"] = self._enum(fields.get("outcome"), OUTCOMES, "error")
        ev["error_code"] = self._code(fields.get("error_code"))
        dur = self._count(fields.get("duration_ms"), default=0)
        ev["duration_ms"] = min(dur or 0, MAX_DURATION_MS)
        ev["response_bytes"] = self._count(fields.get("response_bytes"), default=None)
        ev["arg_keys"] = self._arg_keys(fields.get("arg_keys"))
        ev["write_mode"] = self._enum(fields.get("write_mode", "n/a"), WRITE_MODES, "n/a")
        ev["via_tool"] = _name(fields.get("via_tool"), "via_tool")
        ev["correlation_id"] = self._id(fields.get("correlation_id"))
        ev["parent_correlation_id"] = self._id(fields.get("parent_correlation_id"))
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

    def record_call(
        self,
        *,
        tool: str,
        start: float,
        result: object = None,
        exc: BaseException | None = None,
        kwargs: Mapping[str, Any] | None = None,
        question_key: str = "user_question",
        meta_args: Iterable[str] = META_ARGS,
        denied: frozenset[str] = DENIED_ERRORS,
        **fields: Any,
    ) -> bool:
        """Record a finished Python tool call from its envelope. Never raises.

        ``start`` is the ``time.perf_counter()`` taken before the call. ``kwargs`` are the
        call's keyword arguments: only their names are kept (minus ``meta_args``), and
        ``kwargs[question_key]`` becomes the (redacted) question. Other event fields (user,
        user_kind, tier, client, kind, write_mode, via_tool, correlation_id ...) pass through.
        """
        if self.dir is None:
            return False
        try:
            outcome, code = envelope_outcome(result, exc, denied=denied)
            skip = set(meta_args)
            args = dict(kwargs or {})
            question = args.get(question_key) if isinstance(args.get(question_key), str) else None
            fields.setdefault("question", question)
            return self.record(
                tool=tool,
                outcome=outcome,
                error_code=code,
                duration_ms=(time.perf_counter() - start) * 1000.0,
                response_bytes=response_size(result) if exc is None else None,
                arg_keys=[k for k in args if k not in skip],
                **fields,
            )
        except Exception as err:
            self.write_errors += 1
            self.last_error = type(err).__name__
            return False

    def write_catalog(self, tools: Iterable[Mapping[str, Any]]) -> bool:
        """Write ``tools.json`` (the server's registered tools) atomically. Never raises."""
        if self.dir is None:
            return False
        try:
            rows: list[dict[str, Any]] = []
            for t in tools:
                name = _name(t.get("name"), "tool")
                if not name:
                    continue
                rows.append(
                    {
                        "name": name,
                        "kind": self._enum(t.get("kind", "read"), KINDS, "read"),
                        "domain": _name(t.get("domain"), "tool"),
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
        if isinstance(value, int):
            if 0 <= value <= MAX_COUNT:
                return value
        elif isinstance(value, float) and math.isfinite(value) and 0 <= value <= MAX_COUNT:
            whole = math.floor(value)
            return int(whole) + (1 if value - whole >= 0.5 else 0)  # half-up, as JavaScript Math.round
        self.dropped_fields += 1
        return default

    def _code(self, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, str):
            v = value[: _MAX["error_code"]]
            if _CODE_RE.match(v):
                return v
        self.dropped_fields += 1
        return "unclassified"  # free text (a message) never goes in as a code

    def _id(self, value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, str) and _ID_RE.match(value):
            return value
        self.dropped_fields += 1
        return None

    def _arg_keys(self, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, Mapping):  # a kwargs dict: keep the names, never the values
            value = list(value.keys())
        if isinstance(value, str | bytes) or not isinstance(value, Iterable):
            self.dropped_fields += 1
            return []
        keys: set[str] = set()
        for k in value:
            if isinstance(k, str) and _ARG_RE.match(k) and len(_ARG_DIGITS_RE.findall(k)) < 5:
                keys.add(k)
        return sorted(keys)[:_MAX_ARG_KEYS]


def _name(value: object, field: str) -> str | None:
    """A tool / server / domain name: only [A-Za-z0-9_.:-] survive, so no free text gets in."""
    if not isinstance(value, str):
        return None
    return _TOOL_STRIP_RE.sub("", value)[: _MAX[field]] or None


def elapsed_ms(start: float) -> int:
    """Milliseconds since a ``time.perf_counter()`` start."""
    return math.floor((time.perf_counter() - start) * 1000 + 0.5)
