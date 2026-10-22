"""The spike resource server: a FastMCP server with one tool, put behind the
broker in required mode. Used to prove that claude.ai, Claude Desktop and
Claude Code follow an authorization server on another host (bb-identity
docs/SPIKE_A2.md).

    SPIKE_IDENTITY_MODE=required \
    SPIKE_IDENTITY_ISSUER=https://id.bakerbaynes.com/r/spike \
    SPIKE_IDENTITY_RESOURCE=https://spike-mcp.bakerbaynes.com/mcp \
    SPIKE_IDENTITY_VERIFIER_TOKEN=... \
    SPIKE_IDENTITY_SNAPSHOT_URL=http://127.0.0.1:8775/r/spike/snapshot \
    SPIKE_IDENTITY_JWKS_URL=http://127.0.0.1:8775/.well-known/jwks.json \
    uv run python examples/spike_server.py --port 8776
"""

from __future__ import annotations

import argparse
import logging

import uvicorn
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_request

from bb_mcp_identity import IdentityConfig, IdentityMiddleware, Verifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

mcp = FastMCP("identity-spike")


@mcp.tool()
def spike_whoami() -> dict[str, object]:
    """Who the broker says you are (the proof that identity flowed end to end)."""
    request = get_http_request()
    principal = getattr(request.state, "identity_principal", None)
    if principal is None:
        return {"ok": False, "error": "no principal on the request"}
    return {
        "ok": True,
        "sub": principal.sub,
        "username": principal.username,
        "tier": principal.tier,
        "scopes": list(principal.scopes),
        "client_id": principal.client_id,
        "auth_time": principal.auth_time,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8776)
    args = parser.parse_args()
    config = IdentityConfig.from_env("SPIKE", realm="identity-spike")
    if not config.required:
        raise SystemExit("the spike runs in required mode only: set SPIKE_IDENTITY_MODE=required")
    verifier = Verifier(config)
    verifier.start()
    app = IdentityMiddleware(mcp.http_app(path="/mcp"), verifier, mcp_path="/mcp", scopes_supported=["spike:read"])
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
