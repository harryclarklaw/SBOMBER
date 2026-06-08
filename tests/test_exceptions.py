"""Tests for the exceptions (allowlist) loader and matching."""

from __future__ import annotations

import pytest

from sbom_counsel.errors import ConfigError
from sbom_counsel.policy import load_exceptions_from_text

VALID = """
exceptions:
  - component: leftpad
    version: "1.3.0"
    posture: allowed
    justification: Build-time dev dependency only; not distributed.
    owner: Jane Counsel <jane@example.com>
    date: 2026-05-01
  - component: anylib
    version: "*"
    posture: review
    justification: Vendored and patched; tracked separately.
    owner: Legal
    date: 2026-05-02
"""


def test_load_and_match_exact_version() -> None:
    s = load_exceptions_from_text(VALID, "<test>")
    rule = s.find("leftpad", "1.3.0")
    assert rule is not None
    assert rule.posture == "allowed"
    assert rule.owner.startswith("Jane")


def test_no_match_for_other_version() -> None:
    s = load_exceptions_from_text(VALID, "<test>")
    assert s.find("leftpad", "2.0.0") is None


def test_wildcard_matches_any_version() -> None:
    s = load_exceptions_from_text(VALID, "<test>")
    assert s.find("anylib", "9.9.9") is not None
    assert s.find("anylib", None) is not None


def test_name_match_is_case_insensitive() -> None:
    s = load_exceptions_from_text(VALID, "<test>")
    assert s.find("LeftPad", "1.3.0") is not None


def test_exact_version_preferred_over_wildcard() -> None:
    doc = """
exceptions:
  - {component: x, version: "*", posture: review, justification: j, owner: o, date: 2026-01-01}
  - {component: x, version: "1.0.0", posture: allowed, justification: j, owner: o, date: 2026-01-01}
"""
    s = load_exceptions_from_text(doc, "<test>")
    rule = s.find("x", "1.0.0")
    assert rule is not None
    assert rule.posture == "allowed"


def test_empty_documents_yield_empty_set() -> None:
    assert not load_exceptions_from_text("", "<t>")
    assert not load_exceptions_from_text("exceptions:", "<t>")
    assert not load_exceptions_from_text("exceptions: []", "<t>")


_FULL = {
    "component": "x",
    "version": "1",
    "posture": "allowed",
    "justification": "j",
    "owner": "o",
    "date": "2026-01-01",
}


def _doc(**overrides: object) -> str:
    fields = {**_FULL, **overrides}
    fields = {k: v for k, v in fields.items() if v is not None}
    body = "".join(f"    {k}: {v!r}\n" for k, v in fields.items())
    return "exceptions:\n  -\n" + body


@pytest.mark.parametrize(
    "doc,fragment",
    [
        (_doc(justification=None), "justification"),
        (_doc(owner=None), "owner"),
        (_doc(date=None), "date"),
        (_doc(posture="nope"), "invalid posture"),
        (_doc(date="notadate"), "invalid date"),
        (_doc(version=None), "missing 'version'"),
    ],
)
def test_invalid_exceptions_raise_config_error(doc: str, fragment: str) -> None:
    with pytest.raises(ConfigError) as exc:
        load_exceptions_from_text(doc, "<test>")
    assert fragment in str(exc.value).lower() or fragment in str(exc.value)


def test_missing_justification_is_rejected() -> None:
    doc = """
exceptions:
  - component: x
    version: "1"
    posture: allowed
    owner: o
    date: 2026-01-01
"""
    with pytest.raises(ConfigError, match="justification"):
        load_exceptions_from_text(doc, "<test>")
