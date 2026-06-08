"""Load, validate, and evaluate the licence policy.

The policy is the lawyer's lever: an external YAML file that maps licences to
categories and categories to ship-postures and obligations. None of this lives
in code. This module loads that file, validates it with actionable error
messages, and exposes :meth:`Policy.classify_license`, which turns a single
normalised SPDX licence id into an auditable :class:`SymbolClassification`.
"""

from __future__ import annotations

import dataclasses
import importlib.resources
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..errors import ConfigError
from ..licensing import normalize_key
from ..models import ALL_POSTURES, Posture, PolicyMeta, SymbolClassification

_DATA_PACKAGE = "sbom_counsel.data"
_DEFAULT_POLICY_FILE = "default_policy.yaml"


@dataclass(frozen=True)
class Category:
    """A licence category: its description, ship-posture, and obligations."""

    key: str
    description: str
    posture: Posture
    obligations: tuple[str, ...]


@dataclass(frozen=True)
class Policy:
    """A loaded, validated licence policy."""

    meta: PolicyMeta
    categories: dict[str, Category]
    license_map: dict[str, str]
    expression_map: dict[str, str]
    notes: dict[str, str]
    unresolved_category: str

    @property
    def unresolved_posture(self) -> Posture:
        return self.categories[self.unresolved_category].posture

    def with_unresolved_posture(self, posture: Posture) -> Policy:
        """Return a copy of this policy with the unresolved category's posture set.

        Used by the ``--strict-unresolved`` option to escalate unknowns to
        ``blocked`` without editing the policy file.
        """
        current = self.categories[self.unresolved_category]
        updated = Category(
            key=current.key,
            description=current.description,
            posture=posture,
            obligations=current.obligations,
        )
        new_categories = dict(self.categories)
        new_categories[self.unresolved_category] = updated
        return dataclasses.replace(self, categories=new_categories)

    def category_for_expression(self, expression: str) -> str | None:
        """Return the category for a full SPDX expression, if a rule exists."""
        return self.expression_map.get(expression)

    def classify_license(self, key: str, *, rule_prefix: str = "license") -> SymbolClassification:
        """Classify a single recognised SPDX licence id against the policy.

        Always returns a result. A recognised licence that the policy does not
        map is treated conservatively as the unresolved category, with a note
        that it was recognised but not categorised.
        """
        category_key = self.license_map.get(key)
        note = self.notes.get(key)
        if category_key is None:
            category = self.categories[self.unresolved_category]
            unmapped_note = (
                f"Licence '{key}' is a recognised SPDX id but is not categorised by "
                f"this policy; treated conservatively and flagged for review."
            )
            return SymbolClassification(
                license_key=key,
                known=True,
                category=self.unresolved_category,
                posture=category.posture,
                rule_id=f"default:unmapped:{key}",
                obligations=category.obligations,
                note=unmapped_note,
            )
        category = self.categories[category_key]
        return SymbolClassification(
            license_key=key,
            known=True,
            category=category_key,
            posture=category.posture,
            rule_id=f"{rule_prefix}:{key}->{category_key}",
            obligations=category.obligations,
            note=note,
        )

    def unresolved_classification(self, key: str, reason: str) -> SymbolClassification:
        """Build the classification for an unresolved component."""
        category = self.categories[self.unresolved_category]
        return SymbolClassification(
            license_key=key,
            known=False,
            category=self.unresolved_category,
            posture=category.posture,
            rule_id="default:unresolved",
            obligations=category.obligations,
            note=reason,
        )


# --- Loading & validation ----------------------------------------------------


def _require_mapping(value: Any, what: str, source: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(
            f"Policy {what} must be a mapping, got {type(value).__name__}.",
            hint=f"Check the '{what}' section of {source}.",
        )
    return value


def _coerce_posture(value: Any, where: str, source: str) -> Posture:
    if not isinstance(value, str) or value not in ALL_POSTURES:
        allowed = ", ".join(ALL_POSTURES)
        raise ConfigError(
            f"Invalid posture {value!r} for {where}; must be one of: {allowed}.",
            hint=f"Edit {where} in {source}.",
        )
    return value  # type: ignore[return-value]


def _coerce_str_list(value: Any, where: str, source: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(
            f"'{where}' must be a list of strings.",
            hint=f"Check {where} in {source}.",
        )
    return tuple(value)


def _parse_categories(raw: dict[str, Any], source: str) -> dict[str, Category]:
    categories_raw = _require_mapping(raw.get("categories"), "categories", source)
    if not categories_raw:
        raise ConfigError(
            "Policy defines no categories.",
            hint=f"Add a 'categories:' section to {source}.",
        )
    categories: dict[str, Category] = {}
    for key, body in categories_raw.items():
        body = _require_mapping(body, f"categories.{key}", source)
        posture = _coerce_posture(body.get("posture"), f"categories.{key}.posture", source)
        description = body.get("description")
        if description is not None and not isinstance(description, str):
            raise ConfigError(f"categories.{key}.description must be text.")
        obligations = _coerce_str_list(
            body.get("obligations"), f"categories.{key}.obligations", source
        )
        categories[key] = Category(
            key=key,
            description=(description or "").strip(),
            posture=posture,
            obligations=obligations,
        )
    return categories


def _parse_license_map(
    raw: dict[str, Any], categories: dict[str, Category], source: str
) -> dict[str, str]:
    licenses_raw = _require_mapping(raw.get("licenses"), "licenses", source)
    result: dict[str, str] = {}
    for key, category_key in licenses_raw.items():
        if not isinstance(category_key, str) or category_key not in categories:
            raise ConfigError(
                f"Licence '{key}' is mapped to unknown category {category_key!r}.",
                hint=f"Use one of: {', '.join(sorted(categories))}.",
            )
        # Normalise the licence key so deprecated ids (e.g. GPL-2.0) match the
        # resolver's canonical output (GPL-2.0-only). Unknown ids are kept as
        # written (they simply will not match a recognised licence).
        canonical = normalize_key(str(key)) or str(key)
        result[canonical] = category_key
    return result


def _parse_expression_map(
    raw: dict[str, Any], categories: dict[str, Category], source: str
) -> dict[str, str]:
    expressions_raw = _require_mapping(raw.get("expressions"), "expressions", source)
    result: dict[str, str] = {}
    for expression, category_key in expressions_raw.items():
        if not isinstance(category_key, str) or category_key not in categories:
            raise ConfigError(
                f"Expression {expression!r} is mapped to unknown category {category_key!r}.",
                hint=f"Use one of: {', '.join(sorted(categories))}.",
            )
        result[str(expression)] = category_key
    return result


def _parse_notes(raw: dict[str, Any], source: str) -> dict[str, str]:
    notes_raw = _require_mapping(raw.get("notes"), "notes", source)
    result: dict[str, str] = {}
    for key, text in notes_raw.items():
        if not isinstance(text, str):
            raise ConfigError(f"notes.{key} must be text.")
        # Normalise licence-id note keys too; leave full expressions untouched.
        canonical = normalize_key(str(key)) or str(key)
        result[canonical] = text.strip()
    return result


def _parse_policy_document(data: Any, source: str) -> Policy:
    if not isinstance(data, dict):
        raise ConfigError(
            "Policy file must contain a YAML mapping at the top level.",
            hint=f"Check the structure of {source}.",
        )

    meta_raw = _require_mapping(data.get("meta"), "meta", source)
    meta = PolicyMeta(
        name=str(meta_raw.get("name", "Unnamed policy")),
        version=str(meta_raw.get("version", "0")),
        description=str(meta_raw.get("description", "")).strip(),
        source_path=source,
    )

    categories = _parse_categories(data, source)

    defaults_raw = _require_mapping(data.get("defaults"), "defaults", source)
    unresolved_category = str(defaults_raw.get("unresolved_category", "unknown"))
    if unresolved_category not in categories:
        raise ConfigError(
            f"defaults.unresolved_category is {unresolved_category!r}, "
            f"which is not a defined category.",
            hint=f"Add an '{unresolved_category}' category or point this at an existing one.",
        )

    license_map = _parse_license_map(data, categories, source)
    expression_map = _parse_expression_map(data, categories, source)
    notes = _parse_notes(data, source)

    return Policy(
        meta=meta,
        categories=categories,
        license_map=license_map,
        expression_map=expression_map,
        notes=notes,
        unresolved_category=unresolved_category,
    )


def load_policy_from_text(text: str, source: str) -> Policy:
    """Parse and validate a policy from YAML text."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(
            f"Could not parse policy file {source}: {exc}",
            hint="The policy file must be valid YAML.",
        ) from exc
    return _parse_policy_document(data, source)


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy from a file path."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(
            f"Policy file not found: {p}",
            hint="Pass an existing --policy file, or omit it to use the built-in default.",
        ) from exc
    except OSError as exc:
        raise ConfigError(f"Could not read policy file {p}: {exc}") from exc
    return load_policy_from_text(text, str(p))


def default_policy_text() -> str:
    """Return the bundled default policy YAML as text (for `init-policy`)."""
    return (
        importlib.resources.files(_DATA_PACKAGE)
        .joinpath(_DEFAULT_POLICY_FILE)
        .read_text(encoding="utf-8")
    )


def load_default_policy() -> Policy:
    """Load and validate the bundled default policy."""
    return load_policy_from_text(default_policy_text(), f"<bundled {_DEFAULT_POLICY_FILE}>")
