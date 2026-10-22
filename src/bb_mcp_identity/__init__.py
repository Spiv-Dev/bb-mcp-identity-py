"""bb_mcp_identity: the verifier side of the Baker Baynes identity broker.

from bb_mcp_identity import IdentityConfig, Verifier, IdentityMiddleware

cfg = IdentityConfig.from_env("DEV")
verifier = Verifier(cfg)
verifier.start()
app = IdentityMiddleware(mcp.streamable_http_app(), verifier, mcp_path="/mcp")
"""

from .asgi import IdentityMiddleware
from .config import ConfigError, IdentityConfig
from .metadata import protected_resource_metadata, www_authenticate
from .service_principals import ServicePrincipal, ServicePrincipals
from .snapshot import SnapshotStore, SubjectEntry
from .verifier import Deny, Principal, Verifier

__all__ = [
    "ConfigError",
    "Deny",
    "IdentityConfig",
    "IdentityMiddleware",
    "Principal",
    "ServicePrincipal",
    "ServicePrincipals",
    "SnapshotStore",
    "SubjectEntry",
    "Verifier",
    "protected_resource_metadata",
    "www_authenticate",
]

__version__ = "0.1.0"
