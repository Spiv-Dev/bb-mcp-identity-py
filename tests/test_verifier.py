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


NEW_SUB = "005000000000003AAA"


def _add_subject(broker: StubBroker, sub: str, **fields: object) -> None:
    entry = dict(broker.snapshot["subjects"][SUB])
    entry.update(fields)
    broker.snapshot["subjects"][sub] = entry
    broker.snapshot["version"] += 1


def test_first_sign_in_refetches_snapshot_once(broker: StubBroker) -> None:
    v = start(broker)
    _add_subject(broker, NEW_SUB)  # the broker knows the new subject; our copy does not yet
    hits = broker.snapshot_hits
    p = v.verify(broker.mint(sub=NEW_SUB))
    assert p.sub == NEW_SUB
    assert broker.snapshot_hits == hits + 1


def test_new_entitlement_refetches_snapshot(broker: StubBroker) -> None:
    v = start(broker)
    broker.snapshot["subjects"][SUB].update({"tier": None, "scope": None})
    broker.snapshot["version"] += 1
    v.snapshot.fetch()
    broker.snapshot["subjects"][SUB].update({"tier": "Read", "scope": "t:read"})
    broker.snapshot["version"] += 1
    assert v.verify(broker.mint()).tier == "Read"


def test_miss_refresh_is_rate_limited(broker: StubBroker) -> None:
    v = start(broker)
    hits = broker.snapshot_hits
    now = time.time()
    for _ in range(3):
        with pytest.raises(Deny) as exc:
            v.verify(broker.mint(sub=NEW_SUB), now=now)
        assert exc.value.reason == "unknown_subject"
    assert broker.snapshot_hits == hits + 1
    with pytest.raises(Deny):
        v.verify(broker.mint(sub=NEW_SUB), now=now + 6)
    assert broker.snapshot_hits == hits + 2


def test_miss_refresh_can_be_disabled(broker: StubBroker) -> None:
    v = start(broker, T_IDENTITY_MISS_REFRESH_S="0")
    _add_subject(broker, NEW_SUB)
    hits = broker.snapshot_hits
    with pytest.raises(Deny) as exc:
        v.verify(broker.mint(sub=NEW_SUB))
    assert exc.value.reason == "unknown_subject"
    assert broker.snapshot_hits == hits


def test_forged_token_never_triggers_a_fetch(broker: StubBroker) -> None:
    v = start(broker)
    hits = broker.snapshot_hits
    with pytest.raises(Deny):
        v.verify(broker.mint(sub=NEW_SUB, _kid="bbid-unknown"))
    assert broker.snapshot_hits == hits
