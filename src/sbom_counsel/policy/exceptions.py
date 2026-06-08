"""Load and apply project-level exceptions (allowlist overrides).

An exception grants a specific component/version an overriding posture, with a
mandatory audit trail: justification, owner, and date. Exceptions without a
justification are rejected. Applied exceptions are surfaced in the report so a
reviewer can see exactly what was overridden and why.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

from ..errors import ConfigError
from ..models import ALL_POSTURES, Posture


@dataclass(frozen=True)
class ExceptionRule:
    """A single override rule for a component (and version)."""

    component: str
    version: str  # exact version string, or "*" to match any version.
    posture: Posture
    justification: str
    owner: str
    date: str

    def matches(self, name: str, version: str | None) -> bool:
        if name.casefold() != self.component.casefold():
            return False
        if self.version == "*":
            return True
        return (version or "") == self.version


@dataclass(frozen=True)
class ExceptionSet:
    """A collection of exception rules, with first-match lookup."""

    rules: tuple[ExceptionRule, ...]
    source_path: str | None = None

    def find(self, name: str, version: str | None) -> ExceptionRule | None:
        """Return the first matching rule, preferring an exact-version match."""
        exact = [r for r in self.rules if r.matches(name, version) and r.version != "*"]
        if exact:
            return exact[0]
        for rule in self.rules:
            if rule.matches(name, version):
                return rule
        return None

    def __bool__(self) -> bool:
        return bool(self.rules)


_EMPTY = ExceptionSet(rules=())


def empty_exception_set() -> ExceptionSet:
    return _EMPTY


def _require_str(value: Any, field: str, index: int, source: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(
            f"Exception #{index + 1} in {source} is missing a non-empty '{field}'.",
            hint="Each exception requires component, version, posture, justification, owner, and date.",
        )
    return value.strip()


def _parse_rule(body: Any, index: int, source: str) -> ExceptionRule:
    if not isinstance(body, dict):
        raise ConfigError(f"Exception #{index + 1} in {source} must be a mapping.")

    component = _require_str(body.get("component"), "component", index, source)
    # Version may be given as "*" or a string; numbers are coerced to text.
    raw_version = body.get("version")
    if raw_version is None or (isinstance(raw_version, str) and not raw_version.strip()):
        raise ConfigError(
            f"Exception #{index + 1} ({component}) in {source} is missing 'version'.",
            hint="Use an exact version string, or '*' to match any version.",
        )
    version = str(raw_version).strip()

    posture_value = body.get("posture")
    if not isinstance(posture_value, str) or posture_value not in ALL_POSTURES:
        raise ConfigError(
            f"Exception #{index + 1} ({component}) in {source} has invalid posture "
            f"{posture_value!r}; must be one of: {', '.join(ALL_POSTURES)}.",
        )

    # Justification is mandatory — exceptions without one are rejected.
    justification = _require_str(body.get("justification"), "justification", index, source)
    owner = _require_str(body.get("owner"), "owner", index, source)

    # YAML parses an unquoted ISO date into a date/datetime object; accept both
    # that and an explicit string, and always store a normalised YYYY-MM-DD.
    raw_date = body.get("date")
    if isinstance(raw_date, datetime):
        date_str = raw_date.date().isoformat()
    elif isinstance(raw_date, date):
        date_str = raw_date.isoformat()
    else:
        date_str = _require_str(raw_date, "date", index, source)
        try:
            date_str = date.fromisoformat(date_str).isoformat()
        except ValueError as exc:
            raise ConfigError(
                f"Exception #{index + 1} ({component}) in {source} has an invalid date "
                f"{date_str!r}; use ISO format YYYY-MM-DD.",
            ) from exc

    return ExceptionRule(
        component=component,
        version=version,
        posture=posture_value,  # type: ignore[arg-type]
        justification=justification,
        owner=owner,
        date=date_str,
    )


def load_exceptions_from_text(text: str, source: str) -> ExceptionSet:
    """Parse and validate exceptions from YAML text."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Could not parse exceptions file {source}: {exc}",
            hint="The exceptions file must be valid YAML.",
        ) from exc

    if data is None:
        return ExceptionSet(rules=(), source_path=source)
    if isinstance(data, dict):
        items = data.get("exceptions")
    else:
        items = data
    if items is None:
        return ExceptionSet(rules=(), source_path=source)
    if not isinstance(items, list):
        raise ConfigError(
            f"Exceptions file {source} must contain a list under 'exceptions:'.",
        )

    rules = tuple(_parse_rule(item, index, source) for index, item in enumerate(items))
    return ExceptionSet(rules=rules, source_path=source)


def load_exceptions(path: str | Path) -> ExceptionSet:
    """Load and validate exceptions from a file path."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(
            f"Exceptions file not found: {p}",
            hint="Pass an existing --exceptions file, or omit it.",
        ) from exc
    except OSError as exc:
        raise ConfigError(f"Could not read exceptions file {p}: {exc}") from exc
    return load_exceptions_from_text(text, str(p))
