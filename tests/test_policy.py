"""Tests for policy loading, validation, and evaluation."""

from __future__ import annotations

import pytest

from sbom_counsel.errors import ConfigError
from sbom_counsel.policy import load_default_policy, load_policy_from_text

MINIMAL = """
meta: {name: Test, version: "1", description: d}
defaults: {unresolved_category: unknown}
categories:
  permissive: {description: p, posture: allowed, obligations: [keep notices]}
  unknown: {description: u, posture: review}
licenses:
  MIT: permissive
  GPL-2.0: permissive
"""


def test_default_policy_loads_and_has_expected_postures() -> None:
    p = load_default_policy()
    assert p.categories["permissive"].posture == "allowed"
    assert p.categories["strong_copyleft"].posture == "blocked"
    assert p.categories["network_copyleft"].posture == "blocked"
    assert p.categories["non_commercial"].posture == "blocked"
    assert p.categories["weak_copyleft"].posture == "review"
    assert p.categories["unknown"].posture == "review"
    assert p.unresolved_posture == "review"


def test_classify_known_permissive() -> None:
    p = load_default_policy()
    c = p.classify_license("MIT")
    assert c.category == "permissive"
    assert c.posture == "allowed"
    assert c.known is True
    assert "MIT" in c.rule_id
    assert c.obligations  # non-empty


def test_classify_strong_and_network_copyleft() -> None:
    p = load_default_policy()
    assert p.classify_license("GPL-3.0-only").posture == "blocked"
    assert p.classify_license("AGPL-3.0-only").posture == "blocked"


def test_apache_carries_a_note() -> None:
    p = load_default_policy()
    c = p.classify_license("Apache-2.0")
    assert c.note is not None
    assert "NOTICE" in c.note


def test_recognised_but_unmapped_licence_is_conservative() -> None:
    p = load_default_policy()
    # "Sleepycat" is a real SPDX id not present in the default map.
    c = p.classify_license("Sleepycat")
    assert c.known is True
    assert c.category == p.unresolved_category
    assert c.posture == "review"
    assert c.rule_id.startswith("default:unmapped")
    assert "not categorised" in (c.note or "")


def test_expression_rule_lookup() -> None:
    p = load_default_policy()
    assert (
        p.category_for_expression("GPL-2.0-only WITH Classpath-exception-2.0") == "weak_copyleft"
    )
    assert p.category_for_expression("MIT") is None


def test_unresolved_classification() -> None:
    p = load_default_policy()
    c = p.unresolved_classification("(none)", "no licence information found")
    assert c.known is False
    assert c.posture == "review"
    assert c.rule_id == "default:unresolved"
    assert c.note == "no licence information found"


def test_deprecated_keys_are_normalised_on_load() -> None:
    p = load_policy_from_text(MINIMAL, "<test>")
    # "GPL-2.0" in the file is normalised to GPL-2.0-only and matches resolver output.
    c = p.classify_license("GPL-2.0-only")
    assert c.category == "permissive"


@pytest.mark.parametrize(
    "doc,fragment",
    [
        ("not a mapping", "mapping at the top level"),
        (
            "categories: {permissive: {posture: maybe}}\ndefaults: {unresolved_category: permissive}",
            "Invalid posture",
        ),
        (
            "categories: {unknown: {posture: review}}\n"
            "defaults: {unresolved_category: unknown}\n"
            "licenses: {MIT: nope}",
            "unknown category",
        ),
        (
            "categories: {permissive: {posture: allowed}}\n"
            "defaults: {unresolved_category: missing}",
            "not a defined category",
        ),
        ("categories: {}\ndefaults: {unresolved_category: unknown}", "no categories"),
    ],
)
def test_invalid_policies_raise_config_error(doc: str, fragment: str) -> None:
    with pytest.raises(ConfigError) as exc:
        load_policy_from_text(doc, "<test>")
    assert fragment in str(exc.value)


def test_invalid_yaml_raises_config_error() -> None:
    with pytest.raises(ConfigError):
        load_policy_from_text("categories: {permissive: {posture: allowed}\n:::bad", "<test>")
