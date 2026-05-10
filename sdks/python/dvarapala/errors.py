class PolicyError(Exception):
    """Base error for policy operations."""


class PolicyDenied(PolicyError):
    """Raised when a tool call is denied by policy."""

    def __init__(self, rule: str, reason: str) -> None:
        self.rule = rule
        self.reason = reason
        super().__init__(f"denied by rule {rule!r}: {reason}")
