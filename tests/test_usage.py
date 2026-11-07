"""The usage ledger: event shape, redaction, never-raise, rotation and prune. All synthetic."""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from bb_mcp_identity.usage import (
    FIELD_ORDER,
    QUESTION_LIMIT,
    UsageLedger,
    redact_question,
    user_slug,
)

SPEC = Path(__file__).resolve().parent.parent / "spec"
SCHEMA = json.loads((SPEC / "usage_event_v1.json").read_text(encoding="utf-8"))
FIXTURES = json.loads((SPEC / "redaction_fixtures_v1.json").read_text(encoding="utf-8"))

# The spec files are shared with bb-mcp-identity-ts, which pins the same hashes. Changing either
# file means changing it in both repos and updating both pins.
SCHEMA_SHA256 = "57cec545cecf3b44c163bd2501e0dbafe5319ace31cc572d1d9cda14a8b69789"
FIXTURES_SHA256 = "5f894707aaadb89f55b2e5e2d55993526e31493adbb009ac8ced193feb929ee2"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def check_schema(ev: dict[str, Any]) -> None:
    """A small JSON-schema check covering the keywords the v1 schema uses."""
    props = SCHEMA["properties"]
    assert set(ev) == set(SCHEMA["required"]) == set(props)
    for key, rule in props.items():
        val = ev[key]
        if "const" in rule:
            assert val == rule["const"], key
        if "enum" in rule:
            assert val in rule["enum"], key
        types = rule.get("type")
        if types is not None:
            allowed = types if isinstance(types, list) else [types]
            py = {"string": str, "integer": int, "array": list, "null": type(None)}
            assert any(isinstance(val, py[t]) and not isinstance(val, bool) for t in allowed), key
        if isinstance(val, str):
            if "maxLength" in rule:
                assert len(val) <= rule["maxLength"], key
            if "pattern" in rule:
                assert re.search(rule["pattern"], val), (key, val)
        if isinstance(val, int) and "minimum" in rule:
            assert val >= rule["minimum"], key
        if isinstance(val, list):
            assert len(val) <= rule["maxItems"]
            for item in val:
                assert re.search(rule["items"]["pattern"], item), item


def read_lines(d: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in sorted(d.glob("usage-*.jsonl")):
        out.extend(json.loads(line) for line in p.read_text(encoding="utf-8").splitlines())
    return out


@pytest.fixture
def ledger(tmp_path: Path) -> UsageLedger:
    return UsageLedger(tmp_path / "usage", server="testapp", version="1.2.3")


def test_spec_files_are_the_shared_versions() -> None:
    assert _sha(SPEC / "usage_event_v1.json") == SCHEMA_SHA256
    assert _sha(SPEC / "redaction_fixtures_v1.json") == FIXTURES_SHA256


def test_field_order_matches_schema() -> None:
    assert list(FIELD_ORDER) == SCHEMA["required"]


def test_disabled_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TESTAPP_USAGE_DIR", raising=False)
    led = UsageLedger.from_env("TESTAPP", server="testapp")
    assert not led.enabled
    assert led.record(tool="t", outcome="ok", duration_ms=1) is False
    assert led.write_catalog([{"name": "t"}]) is False


def test_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TESTAPP_USAGE_DIR", str(tmp_path / "u"))
    led = UsageLedger.from_env("TESTAPP", server="testapp", version="9")
    assert led.enabled and led.dir == tmp_path / "u"


def test_full_event_validates(ledger: UsageLedger) -> None:
    assert ledger.record(
        tool="dev_ping",
        kind="write",
        user="Mitchell@BakerBaynes.com",
        user_kind="user",
        tier="admin",
        client="claude-ai",
        outcome="ok",
        duration_ms=12.6,
        response_bytes=2048,
        arg_keys=["repo", "dry_run", "_user_question", "_user_id"],
        write_mode="preview",
        via_tool="dev_batch",
        correlation_id="c-1",
        parent_correlation_id="p-1",
        question="Email jane.doe@acme.co.za about the R 12 500 renewal",
    )
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    check_schema(ev)
    assert ev["server"] == "testapp" and ev["server_version"] == "1.2.3"
    assert ev["user"] == "mitchell"
    assert ev["duration_ms"] == 13
    assert ev["arg_keys"] == ["dry_run", "repo"]  # meta params dropped, names sorted
    assert ev["question"] == "Email [email] about the [amount] renewal"
    assert list(ev) == list(FIELD_ORDER)


def test_minimal_event_validates(ledger: UsageLedger) -> None:
    assert ledger.record(tool="t", outcome="denied", duration_ms=0)
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    check_schema(ev)
    assert ev["user"] is None and ev["user_kind"] == "unknown" and ev["kind"] == "read"
    assert ev["write_mode"] == "n/a" and ev["question"] is None and ev["arg_keys"] == []


def test_argument_values_are_never_written(ledger: UsageLedger) -> None:
    secret = "VALUE-THAT-MUST-NOT-APPEAR"
    ledger.record(
        tool="t",
        outcome="ok",
        duration_ms=1,
        arg_keys={"account": secret, "amount": 5},  # a kwargs dict: names kept, values dropped
        args={"x": secret},  # unknown field
        result={"y": secret},  # unknown field
    )
    text = "".join(p.read_text(encoding="utf-8") for p in ledger.dir.glob("*.jsonl"))  # type: ignore[union-attr]
    assert secret not in text
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    assert ev["arg_keys"] == ["account", "amount"]
    assert "args" not in ev and "result" not in ev
    assert ledger.dropped_fields == 2


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("kind", "delete", "read"),
        ("outcome", "maybe", "error"),
        ("user_kind", "robot", "unknown"),
        ("write_mode", "yes", "n/a"),
        ("duration_ms", -5, 0),
        ("duration_ms", float("inf"), 0),
        ("duration_ms", "12", 0),
        ("response_bytes", True, None),
    ],
)
def test_bad_values_fall_back_and_are_counted(ledger: UsageLedger, field: str, value: Any, expected: Any) -> None:
    fields: dict[str, Any] = {"tool": "t", "outcome": "ok", "duration_ms": 1, field: value}
    assert ledger.record(**fields)
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    check_schema(ev)
    assert ev[field] == expected


def test_strings_are_bounded_and_cleaned(ledger: UsageLedger) -> None:
    ledger.record(tool="x" * 500, outcome="ok", duration_ms=1, client="bad\x00client \ud83d", error_code="E" * 99)
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    check_schema(ev)
    assert len(ev["tool"]) == 128 and len(ev["error_code"]) == 64
    assert ev["client"] == "badclient �"


def test_arg_keys_reject_odd_names(ledger: UsageLedger) -> None:
    ledger.record(tool="t", outcome="ok", duration_ms=1, arg_keys=["ok", "-dash", "has space", "x" * 65, 7, ""])
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    assert ev["arg_keys"] == ["ok"]


def test_never_raises_when_the_dir_cannot_be_written(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("not a directory")
    led = UsageLedger(blocker / "usage", server="testapp")
    assert led.record(tool="t", outcome="ok", duration_ms=1) is False
    assert led.write_catalog([{"name": "t"}]) is False
    assert led.write_errors == 2
    assert led.stats()["last_error"] is not None


def test_one_line_per_event_and_utc_day_files(ledger: UsageLedger) -> None:
    day1 = datetime(2026, 11, 5, 23, 59, 59, 999000, tzinfo=UTC)
    day2 = day1 + timedelta(milliseconds=1)
    ledger.record(tool="a", outcome="ok", duration_ms=1, ts=day1)
    ledger.record(tool="b", outcome="ok", duration_ms=1, ts=day2)
    names = sorted(p.name for p in ledger.dir.glob("*.jsonl"))  # type: ignore[union-attr]
    assert names == ["usage-2026-11-05.jsonl", "usage-2026-11-06.jsonl"]
    for p in ledger.dir.glob("*.jsonl"):  # type: ignore[union-attr]
        raw = p.read_bytes()
        assert raw.endswith(b"\n") and raw.count(b"\n") == 1
    assert [e["ts"] for e in read_lines(ledger.dir)] == ["2026-11-05T23:59:59.999Z", "2026-11-06T00:00:00.000Z"]  # type: ignore[arg-type]


def test_old_files_are_pruned(ledger: UsageLedger) -> None:
    assert ledger.dir is not None
    ledger.dir.mkdir(parents=True)
    for day in ("2026-10-20", "2026-10-22", "2026-10-23", "2026-11-04"):
        (ledger.dir / f"usage-{day}.jsonl").write_text("{}\n")
    (ledger.dir / "keep-me.txt").write_text("x")
    ledger.record(tool="t", outcome="ok", duration_ms=1, ts=datetime(2026, 11, 6, 8, tzinfo=UTC))
    left = sorted(p.name for p in ledger.dir.iterdir())
    assert left == ["keep-me.txt", "usage-2026-10-23.jsonl", "usage-2026-11-04.jsonl", "usage-2026-11-06.jsonl"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_file_modes(ledger: UsageLedger) -> None:
    ledger.record(tool="t", outcome="ok", duration_ms=1)
    ledger.write_catalog([{"name": "t"}])
    assert ledger.dir is not None
    for p in ledger.dir.iterdir():
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_catalog(ledger: UsageLedger) -> None:
    assert ledger.write_catalog([{"name": "b_tool", "kind": "write", "domain": "x"}, {"name": "a_tool"}, {"name": None}, {"kind": "read"}])
    assert ledger.dir is not None
    doc = json.loads((ledger.dir / "tools.json").read_text(encoding="utf-8"))
    assert doc["server"] == "testapp" and doc["v"] == 1
    assert doc["tools"] == [
        {"name": "a_tool", "kind": "read", "domain": None},
        {"name": "b_tool", "kind": "write", "domain": "x"},
    ]
    assert not list(ledger.dir.glob(".tools.json.*"))


def test_stats(ledger: UsageLedger) -> None:
    ledger.record(tool="t", outcome="ok", duration_ms=1)
    s = ledger.stats()
    assert s["enabled"] is True and s["written"] == 1 and s["write_errors"] == 0


@pytest.mark.parametrize(
    ("username", "slug"),
    [
        ("Mitchell@BakerBaynes.com", "mitchell"),
        ("jeandre.vr@bakerbaynes.com.sandbox", "jeandre.vr"),
        ("break-glass", "break-glass"),
        ("svc-routines", "svc-routines"),
        ("  ", None),
        ("@nolocal", None),
        (None, None),
    ],
)
def test_user_slug(username: Any, slug: str | None) -> None:
    assert user_slug(username) == slug


# --- redaction ------------------------------------------------------------------------------


@pytest.mark.parametrize("case", FIXTURES["cases"], ids=lambda c: repr(c["in"])[:40])
def test_redaction_fixtures(case: dict[str, Any]) -> None:
    assert redact_question(case["in"]) == case["out"]


def test_redaction_non_string() -> None:
    assert redact_question(None) is None
    assert redact_question(42) is None
    assert redact_question("   ") is None


def test_redaction_properties() -> None:
    """Randomised questions built from synthetic PII: none of it may survive."""
    rng = random.Random(20261106)
    words = ["pipeline", "renewal", "Implementations", "west", "team", "Q3", "for", "the", "deal", "2026"]

    def email() -> str:
        return f"{''.join(rng.choices('abcxyz.', k=6))}x@{''.join(rng.choices('abc', k=4))}.co.za"

    def phone() -> str:
        return rng.choice(["082 555 0123", "+27 71 555 0123", "011-555-0123", "0215550123"])

    def number() -> str:
        return "".join(rng.choices("0123456789", k=rng.choice([9, 13, 16])))

    def amount() -> str:
        return rng.choice(["R 12 500", "R2,5m", "$1,200", "500k", "ZAR 3 940.17", "1 500 rand"])

    makers = [email, phone, number, amount]
    for _ in range(400):
        parts: list[str] = []
        planted: list[str] = []
        for _ in range(rng.randint(5, 140)):
            if rng.random() < 0.15:
                tok = rng.choice(makers)()
                planted.append(tok)
                parts.append(tok)
            else:
                parts.append(rng.choice(words))
        if rng.random() < 0.3:
            parts.append("\U0001f600" * rng.randint(1, 600))
        out = redact_question(" ".join(parts))
        assert out is None or len(out) <= QUESTION_LIMIT
        if out is None:
            continue
        assert not re.search("[\ud800-\udfff]", out)
        assert "@" not in out
        assert not re.search(r"[0-9]{9,}", out)
        for tok in planted:
            assert tok not in out, tok


# --- record_call / envelope mapping -----------------------------------------------------------


def test_envelope_outcome() -> None:
    from bb_mcp_identity.usage import envelope_outcome

    assert envelope_outcome({"ok": True, "rows": []}) == ("ok", None)
    assert envelope_outcome([1, 2]) == ("ok", None)
    assert envelope_outcome({"ok": False, "error": "forbidden"}) == ("denied", "forbidden")
    assert envelope_outcome({"ok": False, "error": "server_in_read_only_mode"}) == ("denied", "server_in_read_only_mode")
    assert envelope_outcome({"ok": False, "error": "rate_limited"}) == ("error", "RATE_LIMITED")
    assert envelope_outcome({"ok": False, "error": "github_404"}) == ("error", "github_404")
    assert envelope_outcome({"ok": False}) == ("error", "error")
    assert envelope_outcome({"ok": False, "error": {"nested": 1}}) == ("error", "dict")
    assert envelope_outcome(None, ValueError("x")) == ("error", "ValueError")
    assert envelope_outcome({"ok": False, "error": "custom_denied"}, denied=frozenset({"custom_denied"})) == (
        "denied",
        "custom_denied",
    )


def test_record_call_maps_a_tool_call(ledger: UsageLedger) -> None:
    import time as _time

    start = _time.perf_counter()
    kwargs = {"repo": "secret-repo-value", "dry_run": True, "user_question": "mail jane@acme.co.za", "user_id": "mitchell"}
    assert ledger.record_call(
        tool="dev_issue_create", start=start, result={"ok": True, "n": 1}, kwargs=kwargs, kind="write", write_mode="preview"
    )
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    check_schema(ev)
    assert ev["outcome"] == "ok" and ev["error_code"] is None
    assert ev["arg_keys"] == ["dry_run", "repo"]
    assert ev["question"] == "mail [email]"
    assert ev["response_bytes"] == len('{"ok":true,"n":1}')
    assert "secret-repo-value" not in json.dumps(ev)


def test_record_call_on_exception_and_denial(ledger: UsageLedger) -> None:
    import time as _time

    ledger.record_call(tool="a", start=_time.perf_counter(), exc=RuntimeError("boom"))
    ledger.record_call(tool="b", start=_time.perf_counter(), result={"ok": False, "error": "forbidden"})
    evs = read_lines(ledger.dir)  # type: ignore[arg-type]
    assert [(e["outcome"], e["error_code"], e["response_bytes"]) for e in evs] == [
        ("error", "RuntimeError", None),
        ("denied", "forbidden", len('{"ok":false,"error":"forbidden"}')),
    ]


def test_record_call_never_raises_on_odd_results(ledger: UsageLedger) -> None:
    import time as _time

    class Weird:
        def __repr__(self) -> str:
            raise RuntimeError("no repr")

    circular: dict[str, Any] = {}
    circular["self"] = circular
    assert ledger.record_call(tool="t", start=_time.perf_counter(), result=circular) is True
    assert ledger.record_call(tool="t", start=_time.perf_counter(), result={"ok": True, "w": Weird()}) in (True, False)
    assert ledger.record_call(tool="t", start=_time.perf_counter(), kwargs={"k": object()}) is True


def test_record_call_off(tmp_path: Path) -> None:
    import time as _time

    led = UsageLedger(None, server="x")
    assert led.record_call(tool="t", start=_time.perf_counter()) is False


def test_tool_scope_nesting() -> None:
    from bb_mcp_identity.usage import tool_scope

    with tool_scope("outer") as p1:
        assert p1 is None
        with tool_scope("inner") as p2:
            assert p2 == "outer"
        with tool_scope("again") as p3:
            assert p3 == "outer"
    with tool_scope("top") as p4:
        assert p4 is None


# --- review hardening -------------------------------------------------------------------------


def test_free_text_never_enters_coded_fields(ledger: UsageLedger) -> None:
    ledger.record(
        tool="dev ping﻿!",
        outcome="error",
        duration_ms=1,
        error_code="Could not find jane@acme.co.za",
        correlation_id="has spaces in it",
        tier="Admin Tier!",
        client="python-requests (+mailto:ops@acme.co.za)",
        arg_keys=["8001015009087", "jane.doe.acme.co.za", "acct12345", "repo", "dry_run"],
    )
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    check_schema(ev)
    assert ev["tool"] == "devping"
    assert ev["error_code"] == "unclassified"
    assert ev["correlation_id"] is None and ev["tier"] is None
    assert "acme.co.za" not in ev["client"]
    assert ev["arg_keys"] == ["dry_run", "repo"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [(10**20, None), (10**400, None), (2**53 - 1, 2**53 - 1), (0.49999999999999994, 0), (2.5, 3), (1e300, None)],
)
def test_counts_are_bounded_and_round_like_javascript(ledger: UsageLedger, value: Any, expected: Any) -> None:
    assert ledger.record(tool="t", outcome="ok", duration_ms=1, response_bytes=value)
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    assert ev["response_bytes"] == expected


def test_duration_is_capped_at_the_store_integer(ledger: UsageLedger) -> None:
    ledger.record(tool="t", outcome="ok", duration_ms=10**12)
    [ev] = read_lines(ledger.dir)  # type: ignore[arg-type]
    assert ev["duration_ms"] == 2**31 - 1


@pytest.mark.parametrize(
    "blob", ["1," * 25000, "a" * 50000, "x@" * 25000, "1 " * 25000, "R1," * 20000], ids=["commas", "letters", "ats", "spaced", "rands"]
)
def test_redaction_stays_fast_on_huge_input(blob: str) -> None:
    import time as _time

    t = _time.perf_counter()
    out = redact_question(blob)
    assert _time.perf_counter() - t < 1.0
    assert out is None or len(out) <= QUESTION_LIMIT
