from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from bb_mcp_identity import ConfigError, Deny, IdentityConfig, IdentityMiddleware, Verifier
from bb_mcp_identity import break_glass as bg

from .conftest import RESOURCE, StubBroker, make_config
from .test_asgi import echo_app

OWNER = "005000000000009AAA"
BEARER, SHA = bg.mint("testapp")


def _iso(delta_s: float) -> str:
    return (datetime.now(UTC) + timedelta(seconds=delta_s)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _armed_env(until_delta_s: float = 3600, **extra: str) -> dict[str, str]:
    env = {
        "T_IDENTITY_BREAK_GLASS_SHA256": SHA,
        "T_IDENTITY_BREAK_GLASS_UNTIL": _iso(until_delta_s),
        "T_IDENTITY_BREAK_GLASS_TIER": "Admin",
        "T_IDENTITY_BREAK_GLASS_OWNER": OWNER,
    }
    env.update(extra)
    return env


def _base_env(mode: str = "required") -> dict[str, str]:
    return {
        "T_IDENTITY_MODE": mode,
        "T_IDENTITY_ISSUER": "https://id.example.test/r/testapp",
        "T_IDENTITY_RESOURCE": RESOURCE,
        "T_IDENTITY_VERIFIER_TOKEN": "bbv_x",
    }


# ── settings ─────────────────────────────────────────────────────────────


def test_mint_shape_and_hash() -> None:
    token, digest = bg.mint("development")
    assert token.startswith("bbg_development_")
    assert len(token) > 50
    assert len(digest) == 64
    assert bg.mint("development")[0] != token


def test_unset_means_no_break_glass() -> None:
    assert IdentityConfig.from_env("T", environ=_base_env()).break_glass is None


def test_hash_without_until_is_configured_but_disarmed() -> None:
    cfg = IdentityConfig.from_env("T", environ={**_base_env(), "T_IDENTITY_BREAK_GLASS_SHA256": SHA.upper()})
    assert cfg.break_glass is not None
    assert cfg.break_glass.sha256 == SHA
    assert not cfg.break_glass.armed(time.time())


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"T_IDENTITY_BREAK_GLASS_UNTIL": "2026-10-28T10:00:00+02:00"}, "SHA256 is not"),
        ({"T_IDENTITY_BREAK_GLASS_SHA256": "nothex"}, "64 hex"),
        ({**_armed_env(), "T_IDENTITY_BREAK_GLASS_UNTIL": "tomorrow"}, "YYYY-MM-DD"),
        ({**_armed_env(), "T_IDENTITY_BREAK_GLASS_UNTIL": "2030-01-01T10:00:00"}, "timezone offset"),
        (_armed_env(until_delta_s=25 * 3600), "at most 24 hours"),
        ({**_armed_env(), "T_IDENTITY_BREAK_GLASS_TIER": ""}, "TIER is required"),
        ({**_armed_env(), "T_IDENTITY_BREAK_GLASS_OWNER": "short"}, "18-char"),
        ({**_armed_env(), "T_IDENTITY_BREAK_GLASS_OWNER": "../../../etc/passw"}, "18-char"),
        ({**_armed_env(), "T_IDENTITY_BREAK_GLASS_OWNER": "0050000000000ééAAA"}, "18-char"),
    ],
)
def test_bad_settings_fail_loudly(extra: dict[str, str], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        IdentityConfig.from_env("T", environ={**_base_env(), **extra})


def test_a_past_until_is_simply_disarmed() -> None:
    cfg = IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env(until_delta_s=-60)})
    assert cfg.break_glass is not None
    assert not cfg.break_glass.armed(time.time())


# ── verification ─────────────────────────────────────────────────────────────


def test_armed_bearer_works_without_broker_or_snapshot() -> None:
    # Points at a broker nobody runs and never fetches keys or a snapshot.
    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env()}))
    p = v.verify(BEARER)
    assert p.kind == "break_glass"
    assert p.sub == OWNER
    assert p.tier == "Admin"
    assert p.username == "break-glass"
    assert p.app == "testapp"


@pytest.mark.parametrize(
    ("extra", "bearer", "reason"),
    [
        ({}, BEARER, "break_glass_not_configured"),
        ({"T_IDENTITY_BREAK_GLASS_SHA256": SHA}, BEARER, "break_glass_not_armed"),
        (_armed_env(until_delta_s=-1), BEARER, "break_glass_not_armed"),
        (_armed_env(), BEARER + "x", "break_glass_mismatch"),
        (_armed_env(), "bbg_testapp_guess", "break_glass_mismatch"),
    ],
)
@pytest.mark.parametrize("mode", ["enabled", "required"])
def test_refusals_are_ours_in_every_mode(extra: dict[str, str], bearer: str, reason: str, mode: str) -> None:
    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(mode), **extra}))
    with pytest.raises(Deny) as exc:
        v.verify(bearer)
    assert exc.value.reason == reason
    assert exc.value.ours is True  # never handed to a legacy validator


def test_off_mode_never_honours_it() -> None:
    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env("off"), **_armed_env()}))
    with pytest.raises(Deny) as exc:
        v.verify(BEARER)
    assert exc.value.reason == "identity_off"


def test_every_use_is_counted_and_alerts_are_throttled(caplog: pytest.LogCaptureFixture) -> None:
    events: list[dict[str, Any]] = []
    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env()}), on_break_glass=events.append)
    now = time.time()
    with caplog.at_level("CRITICAL", logger="bb_mcp_identity.break_glass"):
        v.verify(BEARER, now=now)
        v.verify(BEARER, now=now + 10)
        v.verify(BEARER, now=now + 61)
    assert len(events) == 2
    assert events[0]["event"] == "identity.break_glass_used"
    assert events[0]["owner_sub"] == OWNER
    assert events[1]["uses"] == 3
    # Every use is logged; only the hook is throttled.
    assert sum("BREAK-GLASS bearer used" in r.getMessage() for r in caplog.records) == 3
    health = v.health()["break_glass"]
    assert health["configured"] and health["armed"]
    assert health["uses"] == 3
    assert health["last_used"] is not None


def test_a_failing_alert_hook_never_breaks_the_request() -> None:
    def boom(_: dict[str, Any]) -> None:
        raise RuntimeError("pager down")

    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env()}), on_break_glass=boom)
    assert v.verify(BEARER).kind == "break_glass"


def test_start_announces_an_armed_break_glass(broker: StubBroker, caplog: pytest.LogCaptureFixture) -> None:
    env = {f"T_IDENTITY_BREAK_GLASS_{k}": v for k, v in (("SHA256", SHA), ("UNTIL", _iso(600)), ("TIER", "Admin"), ("OWNER", OWNER))}
    v = Verifier(make_config(broker, "required", **env))
    with caplog.at_level("CRITICAL", logger="bb_mcp_identity.break_glass"):
        v.start()
    v.stop()
    assert any("break-glass ARMED" in r.getMessage() for r in caplog.records)


def test_cli_prints_the_bearer_and_the_hash(capsys: pytest.CaptureFixture[str]) -> None:
    assert bg.main(["development"]) == 0
    out = capsys.readouterr().out
    assert "bbg_development_" in out
    assert "_IDENTITY_BREAK_GLASS_SHA256=" in out
    assert bg.main([]) == 2


@pytest.mark.asyncio
async def test_middleware_lets_the_armed_bearer_through(broker: StubBroker) -> None:
    env = {f"T_IDENTITY_BREAK_GLASS_{k}": v for k, v in (("SHA256", SHA), ("UNTIL", _iso(600)), ("TIER", "Admin"), ("OWNER", OWNER))}
    v = Verifier(make_config(broker, "required", **env))  # keys and snapshot never fetched
    app = IdentityMiddleware(echo_app, v, mcp_path="/mcp")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        ok = await c.post("/mcp", headers={"Authorization": f"Bearer {BEARER}"}, json={})
        bad = await c.post("/mcp", headers={"Authorization": "Bearer bbg_testapp_wrong"}, json={})
    assert ok.status_code == 200
    assert ok.json()["principal"] == OWNER
    assert ok.json()["tier"] == "Admin"
    assert bad.status_code == 401


# ── one strict UNTIL format, the same in both libraries ─────────────────────


@pytest.mark.parametrize(
    "until",
    [
        "2026-11-31T06:00:00Z",  # no 31 November
        "2026-02-30T00:00:00Z",
        "2026-10-28T24:00:00Z",
        "2026-10-28t18:00:00z",  # lowercase separators
        "2026-10-28 18:00:00+02:00",  # space separator
        "20261028T180000+0200",  # basic format
        "2026-10-28T18:00:00+0200",
        "2026-10-28T18:00:00+02",
        "2026-10-28T18Z",
        "2026-10-28T18:00:00.000001Z",  # more than millisecond precision
    ],
)
def test_until_has_one_strict_format(until: str) -> None:
    now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC).timestamp()
    with pytest.raises(ConfigError):
        IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env(), "T_IDENTITY_BREAK_GLASS_UNTIL": until}, now=now)


@pytest.mark.parametrize(
    "until", ["2026-10-28T18:00Z", "2026-10-28T18:00:00Z", "2026-10-28T20:00:00.123+02:00", "2026-10-28T09:00:00-04:00"]
)
def test_until_accepted_forms(until: str) -> None:
    now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC).timestamp()
    cfg = IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env(), "T_IDENTITY_BREAK_GLASS_UNTIL": until}, now=now)
    assert cfg.break_glass is not None and cfg.break_glass.armed(now)


# ── async alert hooks ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_hook_is_awaited_inside_a_running_loop() -> None:
    import asyncio

    sent: list[dict[str, Any]] = []

    async def hook(event: dict[str, Any]) -> None:
        await asyncio.sleep(0)
        sent.append(event)

    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env()}), on_break_glass=hook)
    assert v.verify(BEARER).kind == "break_glass"
    for _ in range(5):
        await asyncio.sleep(0)
    assert len(sent) == 1


def test_async_hook_runs_without_a_loop() -> None:
    sent: list[dict[str, Any]] = []

    async def hook(event: dict[str, Any]) -> None:
        sent.append(event)

    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env()}), on_break_glass=hook)
    v.verify(BEARER)
    assert len(sent) == 1


@pytest.mark.asyncio
async def test_a_failing_async_hook_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    import asyncio

    async def hook(_: dict[str, Any]) -> None:
        raise RuntimeError("n8n down")

    v = Verifier(IdentityConfig.from_env("T", environ={**_base_env(), **_armed_env()}), on_break_glass=hook)
    with caplog.at_level("ERROR", logger="bb_mcp_identity.break_glass"):
        assert v.verify(BEARER).kind == "break_glass"
        for _ in range(5):
            await asyncio.sleep(0)
    assert any("alert hook failed" in r.getMessage() for r in caplog.records)
