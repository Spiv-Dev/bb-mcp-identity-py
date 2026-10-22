from __future__ import annotations

import time
from datetime import date

import pytest

from bb_mcp_identity import ConfigError, IdentityConfig, ServicePrincipals, SnapshotStore
from bb_mcp_identity.service_principals import parse_lines

from .conftest import APP, SUB


def test_from_env_defaults_and_derivations() -> None:
    cfg = IdentityConfig.from_env(
        "DEV",
        environ={
            "DEV_IDENTITY_MODE": "enabled",
            "DEV_IDENTITY_ISSUER": "https://id.example.test/r/development/",
            "DEV_IDENTITY_RESOURCE": "https://development-mcp.example.test/mcp",
            "DEV_IDENTITY_VERIFIER_TOKEN": "bbv_x",
        },
    )
    assert cfg.app == "development"
    assert cfg.issuer == "https://id.example.test/r/development"
    assert cfg.jwks_url == "https://id.example.test/.well-known/jwks.json"
    assert cfg.snapshot_url == "https://id.example.test/r/development/snapshot"
    assert cfg.realm == "dev-mcp"
    assert cfg.enabled and not cfg.required


def test_off_mode_needs_nothing() -> None:
    cfg = IdentityConfig.from_env("X", environ={})
    assert cfg.mode == "off"
    assert not cfg.enabled


@pytest.mark.parametrize(
    "environ",
    [
        {"X_IDENTITY_MODE": "maybe"},
        {"X_IDENTITY_MODE": "required"},
        {"X_IDENTITY_MODE": "required", "X_IDENTITY_ISSUER": "https://id.example.test/notanapp", "X_IDENTITY_RESOURCE": "https://r/mcp"},
        {
            "X_IDENTITY_MODE": "required",
            "X_IDENTITY_ISSUER": "https://id.example.test/r/a",
            "X_IDENTITY_RESOURCE": "https://r/mcp",
            "X_IDENTITY_PINNED_JWKS": "{",
        },
    ],
)
def test_bad_config_raises(environ: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        IdentityConfig.from_env("X", environ=environ)


def test_service_principal_lines() -> None:
    lines = f"# comment\nsvc-n8n:Write:{SUB}:2030-01-01:{'t' * 40}\n"
    sp = parse_lines(lines)
    assert len(sp) == 1
    assert sp[0].name == "svc-n8n"
    assert sp[0].expires == date(2030, 1, 1)
    with pytest.raises(ValueError):
        parse_lines("svc-bad:Write:short:2030-01-01:tok")
    with pytest.raises(ValueError):
        parse_lines(f"human:Write:{SUB}:2030-01-01:{'t' * 40}")


def test_service_principal_usable_follows_owner_and_expiry(tmp_path) -> None:  # type: ignore[no-untyped-def]
    snap = SnapshotStore(url="", verifier_token=None, app=APP, cache_path=None, poll_interval_s=60, timeout_s=1)
    snap._accept(
        {
            "version": 1,
            "generated_at": int(time.time() * 1000),
            "stale_after_s": 1200,
            "app": APP,
            "subjects": {SUB: {"status": "active", "active": True, "not_before": 0, "tier": "Admin", "scope": "t:read"}},
        },
        persist=False,
    )
    sp = parse_lines(
        f"svc-n8n:Write:{SUB}:2030-01-01:{'t' * 40}\nsvc-old:Read:{SUB}:2020-01-01:{'u' * 40}\nsvc-orphan:Read:005000000000009AAA:2030-01-01:{'v' * 40}\n"
    )
    assert ServicePrincipals.usable(sp[0], snap) == (True, "ok")
    assert ServicePrincipals.usable(sp[1], snap) == (False, "expired")
    assert ServicePrincipals.usable(sp[2], snap) == (False, "owner_unknown")
    snap._accept(
        {
            **snap._snapshot,
            "version": 2,
            "subjects": {SUB: {"status": "inactive", "active": False, "not_before": 0, "tier": None, "scope": None}},
        },
        persist=False,
    )
    assert ServicePrincipals.usable(sp[0], snap) == (False, "owner_inactive")
    reg = ServicePrincipals(sp)
    assert reg.match("t" * 40) is sp[0]
    assert reg.match("x" * 40) is None
