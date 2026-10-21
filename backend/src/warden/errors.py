"""Typed errors. Every one of them means deny, refuse or escalate, never allow."""

from __future__ import annotations


class WardenError(Exception):
    """Base class. `code` is a stable, machine-readable reason shown in the UI and audit log."""

    code: str = "error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    @property
    def message(self) -> str:
        return str(self.args[0]) if self.args else self.code


class InputRefused(WardenError):
    """Input is malformed or contains characters Warden won't accept."""

    code = "input_refused"


class CanonicalError(WardenError):
    """A value can't be represented in canonical JSON (and so can't be hashed)."""

    code = "not_canonical"


class ConfigError(WardenError):
    """policy.yaml / targets.yaml / settings are invalid. Warden refuses to start or publish."""

    code = "config_invalid"


class IllegalTransition(WardenError):
    code = "illegal_transition"


class NotFound(WardenError):
    code = "not_found"


class DecidedElsewhere(WardenError):
    """Another channel changed the plan first (compare-and-set lost)."""

    code = "decided_elsewhere"


class NotHuman(WardenError):
    """A non-human actor tried to approve, reject or edit. Invariant 3."""

    code = "not_human"


class ApprovalRefused(WardenError):
    code = "approval_refused"


class DispatchRefused(WardenError):
    code = "dispatch_refused"


class SigningError(WardenError):
    code = "signing_error"


class AuditError(WardenError):
    code = "audit_invalid"
