"""The two things the MCP server must say to clients: the protected-resource
metadata document and the 401 challenge header."""

from __future__ import annotations

from typing import Any

from .config import IdentityConfig


def protected_resource_metadata(config: IdentityConfig, scopes_supported: list[str] | None = None) -> dict[str, Any]:
    scopes = ["mcp"] + [s for s in (scopes_supported or []) if s != "mcp"]
    return {
        "resource": config.resource,
        "authorization_servers": [config.issuer],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
    }


def resource_metadata_url(config: IdentityConfig) -> str:
    """``https://host/.well-known/oauth-protected-resource`` for the resource's origin."""
    origin = config.resource.split("/", 3)
    base = "/".join(origin[:3]) if len(origin) >= 3 else config.resource
    return f"{base}/.well-known/oauth-protected-resource"


def www_authenticate(config: IdentityConfig, *, error: str | None = None) -> str:
    parts = [f'Bearer realm="{config.realm}"', f'resource_metadata="{resource_metadata_url(config)}"']
    if error:
        parts.append(f'error="{error}"')
    return ", ".join(parts)
