"""Tests for the classification layer (the legal-interpretation core)."""

from __future__ import annotations

from pathlib import Path

import pytest

from sbom_counsel.classify import analyze, classify_component
from sbom_counsel.ingest import load_sbom
from sbom_counsel.models import Component, LicenseFinding
from sbom_counsel.policy import (
    load_default_policy,
    load_exceptions_from_text,
)


@pytest.fixture
def policy():
    return load_default_policy()


def comp(name: str, *findings: LicenseFinding, version: str = "1.0.0") -> Component:
    return Component(name=name, version=version, licenses=tuple(findings))


def lic(raw: str, source: str = "declared") -> LicenseFinding:
    return LicenseFinding(raw=raw, kind="expression", source=source)  # type: ignore[arg-type]


def test_permissive_is_allowed(policy) -> None:
    r = classify_component(comp("a", lic("MIT")), policy)
    assert r.base_posture == "allowed"
    assert not r.unresolved
    assert r.symbol_classifications[0].rule_id.startswith("license:MIT")


def test_strong_copyleft_is_blocked(policy) -> None:
    r = classify_component(comp("a", lic("GPL-3.0-only")), policy)
    assert r.base_posture == "blocked"


def test_network_copyleft_is_blocked(policy) -> None:
    r = classify_component(comp("a", lic("AGPL-3.0-only")), policy)
    assert r.base_posture == "blocked"
    assert "network" in r.posture_explanation.lower() or any(
        "network" in o.lower() for o in r.obligations
    )


def test_or_chooses_most_permissive(policy) -> None:
    # Dual licensing: MIT OR GPL-3.0-only -> may pick MIT -> allowed.
    r = classify_component(comp("a", lic("MIT OR GPL-3.0-only")), policy)
    assert r.base_posture == "allowed"
    # Both options are still recorded for transparency.
    keys = {s.license_key for s in r.symbol_classifications}
    assert keys == {"MIT", "GPL-3.0-only"}
    assert "most permissive" in r.posture_explanation


def test_and_takes_most_restrictive(policy) -> None:
    # MIT AND GPL-3.0-only -> must satisfy both -> blocked.
    r = classify_component(comp("a", lic("MIT AND GPL-3.0-only")), policy)
    assert r.base_posture == "blocked"
    assert "most restrictive" in r.posture_explanation


def test_with_expression_rule_matches(policy) -> None:
    # The Classpath exception rule downgrades GPL-2.0-only to weak copyleft.
    r = classify_component(comp("a", lic("GPL-2.0-only WITH Classpath-exception-2.0")), policy)
    assert r.base_posture == "review"  # weak_copyleft
    assert r.symbol_classifications[0].rule_id.startswith("expression:")


def test_with_unruled_uses_base_and_flags_exception(policy) -> None:
    # No rule for this WITH; base GPL-3.0-only stays blocked, exception flagged.
    r = classify_component(comp("a", lic("GPL-3.0-only WITH Autoconf-exception-3.0")), policy)
    assert r.base_posture == "blocked"
    assert "exception" in (r.symbol_classifications[0].note or "").lower()


def test_noassertion_is_unresolved_review(policy) -> None:
    r = classify_component(comp("a", lic("NOASSERTION")), policy)
    assert r.unresolved
    assert r.base_posture == "review"
    assert r.symbol_classifications[0].rule_id == "default:unresolved"


def test_non_spdx_identifier_is_unresolved(policy) -> None:
    finding = LicenseFinding("Weird Custom 1.0", "name", "declared")
    r = classify_component(comp("a", finding), policy)
    assert r.unresolved
    assert r.base_posture == "review"


def test_no_licence_is_unresolved(policy) -> None:
    r = classify_component(comp("a"), policy)
    assert r.unresolved
    assert "no licence" in (r.unresolved_reason or "").lower()


def test_partial_unknown_expression_is_unresolved(policy) -> None:
    r = classify_component(comp("a", lic("MIT OR LicenseRef-Mystery")), policy)
    assert r.unresolved
    assert r.base_posture == "review"


def test_unknown_can_be_made_blocked_by_policy() -> None:
    from sbom_counsel.policy import load_policy_from_text

    strict = load_policy_from_text(
        """
meta: {name: strict}
defaults: {unresolved_category: unknown}
categories:
  permissive: {posture: allowed}
  unknown: {posture: blocked, description: strict unknowns}
licenses: {MIT: permissive}
""",
        "<strict>",
    )
    r = classify_component(comp("a", lic("NOASSERTION")), strict)
    assert r.base_posture == "blocked"


def test_exception_overrides_posture_and_is_audited(policy) -> None:
    exceptions = load_exceptions_from_text(
        """
exceptions:
  - component: gpllib
    version: "1.0.0"
    posture: allowed
    justification: Build-time only; not distributed in the shipped binary.
    owner: Counsel
    date: 2026-01-01
""",
        "<exc>",
    )
    c = comp("gpllib", lic("GPL-3.0-only"))
    r = classify_component(c, policy, exceptions)
    assert r.base_posture == "blocked"
    assert r.final_posture == "allowed"
    assert r.exception is not None
    assert r.exception.original_posture == "blocked"
    assert r.exception.justification.startswith("Build-time")


def test_apache_obligations_present(policy) -> None:
    r = classify_component(comp("a", lic("Apache-2.0")), policy)
    assert any("notices" in o.lower() for o in r.obligations)
    assert r.symbol_classifications[0].note is not None


def test_analyze_overall_posture_is_worst(policy, cyclonedx_hardcases_path: Path) -> None:
    sbom = load_sbom(cyclonedx_hardcases_path)
    result = analyze(sbom, policy)
    # The fixture contains AGPL and GPL components, so overall must be blocked.
    assert result.overall_posture == "blocked"
    assert result.counts.total == len(sbom.components)
    assert result.counts.blocked >= 1
    assert result.counts.unresolved >= 1


def test_analyze_counts_consistent(policy, spdx_hardcases_path: Path) -> None:
    result = analyze(load_sbom(spdx_hardcases_path), policy)
    c = result.counts
    assert c.allowed + c.review + c.blocked == c.total


def test_empty_sbom_is_allowed(policy) -> None:
    from sbom_counsel.models import Sbom

    empty = Sbom(sbom_format="cyclonedx", spec_version="1.5", components=())
    result = analyze(empty, policy)
    assert result.overall_posture == "allowed"
    assert result.counts.total == 0


def test_gate_failed_flag(policy, cyclonedx_hardcases_path: Path) -> None:
    sbom = load_sbom(cyclonedx_hardcases_path)
    blocked_gate = analyze(sbom, policy, gate_fail_on=("blocked",))
    assert blocked_gate.gate_failed is True
    no_gate = analyze(sbom, policy)
    assert no_gate.gate_failed is False
