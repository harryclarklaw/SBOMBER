"""Resolve raw SBOM licence statements into normalised SPDX expressions.

This module is a thin, well-defined layer over the ``license-expression``
library (which carries the full SPDX licence and exception lists and an
SPDX-compliant expression parser). It does not classify anything — it only
answers "what licence expression, in normalised SPDX form, applies to this
component, and is it fully recognised?". Classification of the resulting
expression against the policy happens in :mod:`sbom_counsel.classify`.

Design decisions that matter legally:

* Concluded licence information is preferred over declared information, because
  a concluded value is a curator's determination.
* When a component carries several separate licence statements with no explicit
  SPDX expression joining them, their relationship is unspecified. We join them
  conjunctively (``AND``), which is the conservative reading: all stated terms
  must be satisfied. The classifier records this assumption so a reviewer can
  see it.
* ``NOASSERTION`` and ``NONE`` are treated as explicitly unresolved, never as
  "no obligations". A licence that cannot be recognised as SPDX is unresolved.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import license_expression as le

from ..models import LicenseFinding, LicenseSource

# SPDX sentinels that mean "no licence asserted/identified" rather than a licence.
# NOASSERTION: the producer did not make a determination.
# NONE: the producer determined no licence is present (rights reserved by default).
_SENTINELS = {"NOASSERTION", "NONE"}


@lru_cache(maxsize=1)
def _licensing() -> Any:
    """Return a cached SPDX ``Licensing`` (loads the bundled SPDX lists once)."""
    return le.get_spdx_licensing()


def is_known(key: str) -> bool:
    """Return True if ``key`` is a recognised SPDX licence or exception id."""
    return key in _licensing().known_symbols


def normalize_key(raw: str) -> str | None:
    """Normalise a single licence token to its canonical SPDX id.

    Returns the canonical id (resolving deprecated ids, e.g. ``GPL-2.0`` to
    ``GPL-2.0-only``) when the token is a single recognised licence, otherwise
    ``None``.
    """
    try:
        parsed = _licensing().parse(raw, validate=False)
    except le.ExpressionError:
        return None
    if parsed is None or not isinstance(parsed, le.LicenseSymbol):
        return None
    key = str(parsed)
    return key if is_known(key) else None


@dataclass(frozen=True)
class ResolvedSymbol:
    """A single licence/exception symbol extracted from a resolved expression."""

    key: str
    known: bool
    is_exception: bool


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving a component's licence statements.

    ``expression`` is the parsed ``license-expression`` AST (or ``None`` when
    nothing could be resolved). It is transient and is not serialised; the
    classifier walks it and the report uses ``normalized``.
    """

    normalized: str | None
    expression: Any | None
    source: LicenseSource | None
    unresolved: bool
    unresolved_reason: str | None
    symbols: tuple[ResolvedSymbol, ...]

    @property
    def has_unknown_symbol(self) -> bool:
        return any(not s.known for s in self.symbols)


def _combine(raws: Sequence[str]) -> str:
    """Join several raw licence statements conjunctively, parenthesising each."""
    if len(raws) == 1:
        return raws[0]
    return " AND ".join(f"({raw})" for raw in raws)


def _sentinel_reason(raw: str) -> str:
    token = raw.strip().upper()
    if token == "NONE":
        return "no licence present in component (SPDX NONE); rights are reserved by default"
    return "licence not asserted (NOASSERTION)"


def _extract_symbols(parsed: Any) -> tuple[ResolvedSymbol, ...]:
    lic = _licensing()
    out: list[ResolvedSymbol] = []
    seen: set[str] = set()
    for sym in lic.license_symbols(parsed, unique=False, decompose=True):
        key = str(sym)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            ResolvedSymbol(
                key=key,
                known=is_known(key),
                is_exception=bool(getattr(sym, "is_exception", False)),
            )
        )
    return tuple(out)


def resolve(findings: Iterable[LicenseFinding]) -> Resolution:
    """Resolve a component's licence findings into a normalised SPDX expression.

    Tries concluded statements first, then declared. Returns an unresolved
    :class:`Resolution` (never raises) when nothing usable is found, when only
    sentinels are present, when the expression cannot be parsed, or when it
    contains identifiers that are not recognised as SPDX.
    """
    lic = _licensing()
    findings = list(findings)
    by_source: dict[LicenseSource, list[LicenseFinding]] = {"concluded": [], "declared": []}
    for finding in findings:
        by_source[finding.source].append(finding)

    pending_reason = "no licence information found"

    ordered_sources: tuple[LicenseSource, ...] = ("concluded", "declared")
    for source in ordered_sources:
        group = by_source[source]
        if not group:
            continue

        usable = [f for f in group if f.raw.strip() and f.raw.strip().upper() not in _SENTINELS]
        if not usable:
            # The whole group is sentinels; remember why and try the next source.
            pending_reason = _sentinel_reason(group[0].raw)
            continue

        combined = _combine([f.raw.strip() for f in usable])
        try:
            parsed = lic.parse(combined, validate=False)
        except le.ExpressionError as exc:
            return Resolution(
                normalized=None,
                expression=None,
                source=source,
                unresolved=True,
                unresolved_reason=(
                    f"licence statement could not be parsed as an SPDX expression: "
                    f"{combined!r} ({exc})"
                ),
                symbols=(),
            )
        if parsed is None:
            pending_reason = "licence statement was empty"
            continue

        symbols = _extract_symbols(parsed)
        unknown = [s.key for s in symbols if not s.known]
        if unknown:
            reason = "licence identifier(s) not recognised as SPDX: " + ", ".join(sorted(unknown))
            return Resolution(
                normalized=parsed.render(),
                expression=parsed,
                source=source,
                unresolved=True,
                unresolved_reason=reason,
                symbols=symbols,
            )

        return Resolution(
            normalized=parsed.render(),
            expression=parsed,
            source=source,
            unresolved=False,
            unresolved_reason=None,
            symbols=symbols,
        )

    return Resolution(
        normalized=None,
        expression=None,
        source=None,
        unresolved=True,
        unresolved_reason=pending_reason,
        symbols=(),
    )
