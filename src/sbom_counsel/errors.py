"""Exception hierarchy and process exit codes.

All user-facing failures raise a :class:`SbomCounselError` subclass carrying an
exit code and a clear, actionable message. The CLI catches these and prints the
message to stderr without a stack trace, so the tool never crashes with a raw
traceback on bad input. Unexpected errors are caught at the top level and mapped
to :data:`ExitCode.INTERNAL_ERROR`.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes.

    The values are part of the tool's contract with CI pipelines. ``GATE_FAILED``
    is deliberately distinct from the error codes so a pipeline can tell the
    difference between "the analysis ran and the policy gate tripped" and "the
    analysis could not run".
    """

    SUCCESS = 0
    GATE_FAILED = 1  # Analysis succeeded but the policy gate tripped.
    USAGE_ERROR = 2  # Bad command-line invocation (reserved for Click).
    INPUT_ERROR = 3  # SBOM missing, unreadable, malformed, or unsupported.
    CONFIG_ERROR = 4  # Policy or exceptions file invalid.
    ENVIRONMENT_ERROR = 5  # A required external tool is missing or failed.
    INTERNAL_ERROR = 70  # Unexpected error; please report it.


class SbomCounselError(Exception):
    """Base class for all expected, user-facing errors.

    Carries the :class:`ExitCode` the CLI should return. The string form is what
    is shown to the user, so messages must be specific and actionable.
    """

    exit_code: ExitCode = ExitCode.INTERNAL_ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:
        if self.hint:
            return f"{self.message}\nHint: {self.hint}"
        return self.message


class InputError(SbomCounselError):
    """The SBOM input is missing, unreadable, malformed, or an unsupported format."""

    exit_code = ExitCode.INPUT_ERROR


class UnsupportedFormatError(InputError):
    """The input could not be recognised as a supported SBOM format/version."""


class ConfigError(SbomCounselError):
    """The policy or exceptions file is missing or invalid."""

    exit_code = ExitCode.CONFIG_ERROR


class EnvironmentToolError(SbomCounselError):
    """A required external tool (e.g. cargo-about) is missing or failed."""

    exit_code = ExitCode.ENVIRONMENT_ERROR
