from __future__ import annotations

import time

import pytest

from bb_mcp_identity import Deny, Verifier

from .conftest import RESOURCE, SUB, StubBroker, make_config


def start(broker: StubBroker, mode: str = "required", **extra: str) -> Verifier:
    v = Verifier(make_config(broker, mode, **extra))
    v.keys.fetch()
    v.snapshot.fetch()
    return v


def test_good_token_yields_principal_from_snapshot(broker: StubBroker) -> None:
    v = start(broker)
    p = v.verify(broker.mint())
    assert p.sub == SUB
    assert p.tier == "Admin"
    assert p.scopes == ("t:read", "t:write")
    assert p.username == "alice@example.invalid"
    assert p.kind == "user"


def test_snapshot_scope_wins_over_token_scope(broker: StubBroker) -> None:
    v = start(broker)
    broker.snapshot["subjects"][SUB].update({"tier": "Read", "scope": "t:read"})
    broker.snapshot["version"] = 2
    v.snapshot.fetch()
    p = v.verify(broker.mint(tier="Admin", scope="t:read t:write"))
    assert p.tier == "Read"
    assert p.scopes == ("t:read",)


@pytest.mark.parametrize(
    ("overrides", "reason", "ours"),
    [
        ({"aud": "https://other.example.test/mcp"}, "wrong_audience", True),
        ({"iss": "https://evil.example.test/r/testapp"}, "wrong_issuer", True),
        ({"exp": int(time.time()) - 120}, "expired", True),
        ({"_kid": "bbid-unknown"}, "unknown_kid", True),
        ({"_alg": "HS256"}, "wrong_alg", False),
        ({"sub": "short"}, "malformed_claims", True),
        ({"app": "otherapp"}, "wrong_app", True),
        ({"sub": "005000000000002AAA"}, "unknown_subject", True),
    ],
)
def test_token_level_denials(broker: StubBroker, overrides: dict, reason: str, ours: bool) -> None:
    v = start(broker)
    with pytest.raises(Deny) as exc:
        v.verify(broker.mint(**overrides))
    assert exc.value.reason == reason
    assert exc.value.ours is ours


def test_not_a_jwt_is_not_ours(broker: StubBroker) -> None:
    v = start(broker)
    with pytest.raises(Deny) as exc:
        v.verify("tok_legacy_personal_token_xxxxxxxxxxxxxxxx")
    assert exc.value.reason == "not_a_jwt"
    assert exc.value.ours is False


def test_snapshot_level_denials(broker: StubBroker) -> None:
    v = start(broker)
    entry = broker.snapshot["subjects"][SUB]
    entry.update({"active": False, "status": "inactive", "tier": None, "scope": None})
    broker.snapshot["version"] = 3
    v.snapshot.fetch()
    with pytest.raises(Deny, match="subject_inactive"):
        v.verify(broker.mint())
    entry.update({"active": True, "status": "active", "tier": None, "scope": None})
    broker.snapshot["version"] = 4
    v.snapshot.fetch()
    with pytest.raises(Deny, match="not_entitled"):
        v.verify(broker.mint())
    entry.update({"tier": "Admin", "scope": "t:read", "not_before": int(time.time()) + 5})
    broker.snapshot["version"] = 5
    v.snapshot.fetch()
    with pytest.raises(Deny, match="not_before"):
        v.verify(broker.mint())


def test_stale_or_missing_snapshot_denies(broker: StubBroker) -> None:
    v = start(broker)
    broker.snapshot["generated_at"] = int(time.time() * 1000) - 2_000_000
    broker.snapshot["version"] = 6
    v.snapshot.fetch()
    with pytest.raises(Deny, match="snapshot_stale"):
        v.verify(broker.mint())
    v2 = Verifier(make_config(broker, "required", T_IDENTITY_VERIFIER_TOKEN="wrong"))
    v2.keys.fetch()
    assert v2.snapshot.fetch() is False
    with pytest.raises(Deny, match="no_snapshot"):
        v2.verify(broker.mint())


def test_off_mode_never_verifies(broker: StubBroker) -> None:
    v = Verifier(make_config(broker, "off"))
    with pytest.raises(Deny) as exc:
        v.verify(broker.mint())
    assert exc.value.ours is False


def test_pinned_keys_work_without_the_jwks_endpoint(broker: StubBroker) -> None:
    import json

    cfg = make_config(
        broker, "required", T_IDENTITY_PINNED_JWKS=json.dumps({"keys": [broker.jwk]}), T_IDENTITY_JWKS_URL="http://127.0.0.1:9/nope"
    )
    v = Verifier(cfg)
    v.snapshot.fetch()
    assert v.verify(broker.mint()).sub == SUB
    assert broker.jwks_hits == 0


def test_snapshot_etag_and_cache(broker: StubBroker, tmp_path) -> None:  # type: ignore[no-untyped-def]
    cache = tmp_path / "snap.json"
    v = Verifier(make_config(broker, "required", T_IDENTITY_SNAPSHOT_CACHE=str(cache)))
    assert v.snapshot.fetch() is True
    hits = broker.snapshot_hits
    assert v.snapshot.fetch() is True  # 304
    assert broker.snapshot_hits == hits + 1
    assert cache.exists()
    # A fresh verifier restores from disk before its first poll.
    v2 = Verifier(make_config(broker, "required", T_IDENTITY_SNAPSHOT_CACHE=str(cache), T_IDENTITY_VERIFIER_TOKEN="wrong"))
    assert v2.snapshot.version == broker.snapshot["version"]
    assert v2.snapshot.health()["fresh"] is True


def test_health_shape(broker: StubBroker) -> None:
    v = start(broker)
    h = v.health()
    assert h["mode"] == "required"
    assert h["resource"] == RESOURCE
    assert h["snapshot"]["fresh"] is True
    assert broker.kid in h["keys"]["kids"]
