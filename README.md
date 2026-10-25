# bb-mcp-identity

The verifier side of the Baker Baynes identity broker
([bb-identity](https://github.com/Spiv-Dev/bb-identity)) for the Python MCP
servers. An MCP server adds this library, names the broker in its
protected-resource metadata, and verifies the broker's tokens plus the
entitlement snapshot on every request. It stops being an authorization server.

The contract is `docs/VERIFIER_PROTOCOL.md` in the bb-identity repo.

## Install

```bash
uv add "bb-mcp-identity @ git+https://github.com/Spiv-Dev/bb-mcp-identity-py@v0.1.0"
```

## Wire it in (FastMCP / Starlette)

```python
from bb_mcp_identity import IdentityConfig, IdentityMiddleware, Verifier

config = IdentityConfig.from_env("DEV")  # DEV_IDENTITY_* settings
verifier = Verifier(config)
verifier.start()  # JWKS + snapshot poller (daemon thread)

app = IdentityMiddleware(
    mcp.streamable_http_app(),
    verifier,
    mcp_path="/mcp",
    legacy_bearer_ok=my_token_file_match,  # enabled mode: let legacy human tokens through for now
    mint_internal_token=my_internal_hs256,  # optional: keep the inner auth layer unchanged
    scopes_supported=["dev:read", "dev:write", "dev:destroy"],
)
uvicorn.run(app, host=host, port=port)
```

`mint_internal_token(principal)` lets a server keep its existing HS256
validator and RBAC untouched: the middleware verifies the broker token, then
replaces the `Authorization` header with a short-lived internal token the
server mints for that principal (`sub`, `scope`). Servers that prefer to read
the verified caller directly find it at `request.state.identity_principal`.

## Settings

| Variable (prefix `DEV_`) | Meaning |
|---|---|
| `DEV_IDENTITY_MODE` | `off` (default), `enabled` (broker tokens plus legacy), `required` (broker tokens and service principals only) |
| `DEV_IDENTITY_ISSUER` | `https://id.bakerbaynes.com/r/development` |
| `DEV_IDENTITY_RESOURCE` | this server's MCP URL, the token audience |
| `DEV_IDENTITY_VERIFIER_TOKEN` | from `npm run verifier-token -- development` on the broker; required unless the mode is `off` |
| `DEV_IDENTITY_SNAPSHOT_URL` | default `<issuer>/snapshot`; on the broker's VM use `http://127.0.0.1:8775/r/development/snapshot` |
| `DEV_IDENTITY_JWKS_URL` | default `<broker>/.well-known/jwks.json`; loopback on the broker's VM |
| `DEV_IDENTITY_SNAPSHOT_CACHE` | file path; restored on boot so a restart never starts blind |
| `DEV_IDENTITY_PINNED_JWKS` | optional JWKS JSON for offline verification |
| `DEV_IDENTITY_SERVICE_PRINCIPALS` | optional file of `svc-<name>:<tier>:<owner sub>:<expires>:<token>` lines |

An empty value counts as unset. The issuer, JWKS and snapshot URLs must be
https; plain http is accepted for loopback hosts only (the broker on the same
VM). A bad setting raises `ConfigError` at startup rather than denying every
request at runtime.

## Deny rules (all 401)

No bearer; not an ES256 token with our `kid`; wrong `iss` or `aud`; expired;
no snapshot or a stale one; subject unknown, inactive or frozen; no tier for
this app; `auth_time` at or before the subject's `not_before`. In `enabled` mode a
bearer that is not a broker token at all is handed to `legacy_bearer_ok`.

## Develop

```bash
uv sync --extra dev
uv run pytest
uv run ruff check . && uv run mypy
```
