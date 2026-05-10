"""Dvarapala Python SDK.

Embed MCP security policy enforcement in a Python MCP server.

The SDK is intentionally thin: it delegates detection to the dvarapala
core binary or its sidecars (Presidio, llm-guard). We do NOT reimplement
detection logic in Python — that would be reinventing the wheel and
would drift from the Go core.
"""

from .gateway import Gateway
from .errors import PolicyError, PolicyDenied

__all__ = ["Gateway", "PolicyError", "PolicyDenied"]
__version__ = "0.1.0"
