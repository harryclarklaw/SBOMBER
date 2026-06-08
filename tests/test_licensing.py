"""Tests for the licence resolution layer."""

from __future__ import annotations

from sbom_counsel.licensing import is_known, normalize_key, resolve
from sbom_counsel.models import LicenseFinding


def f(raw: str, kind: str = "expression", source: str = "concluded") -> LicenseFinding:
    return LicenseFinding(raw=raw, kind=kind, source=source)  # type: ignore[arg-type]


def test_single_known_licence_resolves() -> None:
    r = resolve([f("MIT")])
    assert not r.unresolved
    assert r.normalized == "MIT"
    assert r.source == "concluded"
    assert [s.key for s in r.symbols] == ["MIT"]
    assert all(s.known for s in r.symbols)


def test_deprecated_id_is_normalised() -> None:
    r = resolve([f("GPL-2.0")])
    assert not r.unresolved
    assert r.normalized == "GPL-2.0-only"


def test_concluded_preferred_over_declared() -> None:
    r = resolve([f("Apache-2.0", source="declared"), f("MIT", source="concluded")])
    assert r.source == "concluded"
    assert r.normalized == "MIT"


def test_or_expression_extracts_both_symbols() -> None:
    r = resolve([f("MIT OR Apache-2.0")])
    assert not r.unresolved
    assert sorted(s.key for s in r.symbols) == ["Apache-2.0", "MIT"]


def test_and_expression() -> None:
    r = resolve([f("MIT AND GPL-3.0-only")])
    assert not r.unresolved
    assert r.normalized == "MIT AND GPL-3.0-only"


def test_with_exception_expression() -> None:
    r = resolve([f("GPL-2.0-only WITH Classpath-exception-2.0")])
    assert not r.unresolved
    assert any(s.is_exception for s in r.symbols)
    assert {s.key for s in r.symbols} == {"GPL-2.0-only", "Classpath-exception-2.0"}


def test_multiple_findings_joined_conjunctively() -> None:
    r = resolve([f("MIT"), f("ISC")])
    assert not r.unresolved
    # Order-independent, but both must appear and be AND-joined.
    assert r.normalized is not None and "AND" in r.normalized
    assert {s.key for s in r.symbols} == {"MIT", "ISC"}


def test_noassertion_is_unresolved() -> None:
    r = resolve([f("NOASSERTION")])
    assert r.unresolved
    assert "NOASSERTION" in (r.unresolved_reason or "")
    assert r.normalized is None


def test_none_sentinel_is_unresolved_with_distinct_reason() -> None:
    r = resolve([f("NONE")])
    assert r.unresolved
    assert "NONE" in (r.unresolved_reason or "")
    assert "reserved" in (r.unresolved_reason or "")


def test_noassertion_falls_back_to_declared() -> None:
    r = resolve([f("NOASSERTION", source="concluded"), f("MIT", source="declared")])
    assert not r.unresolved
    assert r.source == "declared"
    assert r.normalized == "MIT"


def test_non_spdx_identifier_is_unresolved() -> None:
    r = resolve([f("LicenseRef-MyCorp-Proprietary")])
    assert r.unresolved
    assert r.has_unknown_symbol
    assert "not recognised" in (r.unresolved_reason or "")


def test_no_findings_is_unresolved() -> None:
    r = resolve([])
    assert r.unresolved
    assert r.unresolved_reason == "no licence information found"
    assert r.symbols == ()


def test_unparseable_expression_is_unresolved_not_raised() -> None:
    r = resolve([f("MIT AND AND OR")])
    assert r.unresolved
    assert "could not be parsed" in (r.unresolved_reason or "")


def test_partial_unknown_in_expression_is_unresolved() -> None:
    r = resolve([f("MIT OR LicenseRef-Weird")])
    assert r.unresolved
    assert r.has_unknown_symbol
    # The recognised part is still normalised and surfaced for transparency.
    assert r.normalized is not None


def test_is_known_and_normalize_key_helpers() -> None:
    assert is_known("MIT")
    assert not is_known("LicenseRef-Nope")
    assert normalize_key("GPL-2.0") == "GPL-2.0-only"
    assert normalize_key("Totally-Made-Up") is None
    assert normalize_key("MIT OR Apache-2.0") is None  # not a single symbol
