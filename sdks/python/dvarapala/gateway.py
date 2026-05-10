"""Gateway — thin wrapper around the dvarapala core binary.

Two execution modes:

1. Local subprocess: spawn `dvarapala check` and pipe events. Default and
   simplest — no extra services needed.
2. Hub HTTP: call a running `dvarapala hub` over HTTP. Used in production
   where a single hub serves many MCP servers.
"""

from __future__ import annotations

import functools
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, TypeVar

from .errors import PolicyDenied

T = TypeVar("T")


@dataclass
class Gateway:
    policy_path: str
    hub_url: str | None = None  # if set, use HTTP mode

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Gateway":
        return cls(policy_path=str(Path(path).expanduser().resolve()))

    @classmethod
    def from_env(cls) -> "Gateway":
        return cls(
            policy_path=os.environ.get("DVARAPALA_POLICY", "policy.yaml"),
            hub_url=os.environ.get("DVARAPALA_HUB_URL"),
        )

    def protect(self, fn: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        """Decorator: enforces policy on a tool function.

        The actual check is delegated to the dvarapala binary/hub. Until the
        Go core implements the check API this is a pass-through stub so the
        SDK shape stabilises early.
        """

        @functools.wraps(fn)
        async def wrapped(*args: Any, **kwargs: Any) -> T:
            await self._check(fn.__name__, kwargs)
            return await fn(*args, **kwargs)

        return wrapped

    async def _check(self, tool: str, args: dict[str, Any]) -> None:
        # TODO(scaffold): wire to dvarapala binary subprocess or hub HTTP
        # endpoint once the Go core implements `check`.
        return
