"""Classify components against the policy — the legal-interpretation layer.

This is the centre of the product. It takes each component's resolved SPDX
licence expression and walks the expression tree to derive a ship-posture,
combining operators the way the law works:

* ``A OR B`` — the licensee may choose the most permissive option, so the best
  posture wins (this is how dual licensing such as "MIT OR GPL" is handled).
* ``A AND B`` — every licence must be satisfied, so the most restrictive posture
  wins and obligations accumulate.
* ``A WITH exception`` — the base licence's posture is used unless the policy has
  an explicit rule for the whole expression. An exception never silently
  improves the posture; it is surfaced for review.

Anything unresolved (NOASSERTION/NONE, non-SPDX, unparseable, absent, or an
expression containing any unrecognised identifier) is assigned the policy's
conservative default. Every result records the policy rule(s) that produced it,
so a reviewer can audit exactly why a component was flagged. After classification
a project exception may override the posture, and that override is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import reduce
from typing import Any

import license_expression as le

from . import __version__
from .licensing import resolve
from .models import (
    POSTURE_ALLOWED,
    POSTURE_SEVERITY,
    AnalysisResult,
    AppliedException,
    Component,
    ComponentResult,
    Counts,
    Posture,
    Sbom,
    SymbolClassification,
    worse,
)
from .policy import ExceptionSet, Policy, empty_exception_set

DEFAULT_TOOL_NAME = "sbom-counsel"


def _dedupe(items: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


@dataclass(frozen=True)
class _NodeEval:
    """Result of evaluating one node of a licence-expression tree."""

    posture: Posture
    obligations: tuple[str, ...]
    rule_ids: tuple[str, ...]
    classifications: tuple[SymbolClassification, ...]
    explanation: str


def _eval_symbol(node: Any, policy: Policy) -> _NodeEval:
    key = str(node)
    sc = policy.classify_license(key)
    return _NodeEval(
        posture=sc.posture,
        obligations=sc.obligations,
        rule_ids=(sc.rule_id,),
        classifications=(sc,),
        explanation=f"{key} classified as {sc.category} ({sc.posture})",
    )


def _eval_with(node: Any, policy: Policy) -> _NodeEval:
    full = str(node)
    base_key = str(node.license_symbol)
    exception_key = str(node.exception_symbol)

    category_key = policy.category_for_expression(full)
    if category_key is not None:
        category = policy.categories[category_key]
        sc = SymbolClassification(
            license_key=full,
            known=True,
            category=category_key,
            posture=category.posture,
            rule_id=f"expression:{full}->{category_key}",
            obligations=category.obligations,
            note=policy.notes.get(full),
        )
        return _NodeEval(
            posture=sc.posture,
            obligations=sc.obligations,
            rule_ids=(sc.rule_id,),
            classifications=(sc,),
            explanation=f"{full} matched an expression rule → {category_key} ({sc.posture})",
        )

    # No explicit rule: use the base licence, flag the exception for review.
    base = policy.classify_license(base_key)
    base_note = f"{base.note} " if base.note else ""
    note = (
        f"{base_note}Licence exception '{exception_key}' is present, but the policy has no "
        f"specific rule for the full expression. The base licence's posture is used; the "
        f"exception may permit your use and should be reviewed."
    )
    sc = SymbolClassification(
        license_key=full,
        known=True,
        category=base.category,
        posture=base.posture,
        rule_id=f"{base.rule_id}+exception:{exception_key}",
        obligations=base.obligations,
        note=note,
    )
    return _NodeEval(
        posture=sc.posture,
        obligations=sc.obligations,
        rule_ids=(sc.rule_id,),
        classifications=(sc,),
        explanation=(
            f"{full} classified by its base licence {base_key} ({sc.posture}); "
            f"exception '{exception_key}' not separately ruled and should be reviewed"
        ),
    )


def _combine_and(children: list[_NodeEval]) -> _NodeEval:
    posture = reduce(worse, (c.posture for c in children))
    obligations = _dedupe(tuple(o for c in children for o in c.obligations))
    rule_ids = _dedupe(tuple(r for c in children for r in c.rule_ids))
    classifications = tuple(s for c in children for s in c.classifications)
    inner = ", ".join(c.explanation for c in children)
    return _NodeEval(
        posture=posture,
        obligations=obligations,
        rule_ids=rule_ids,
        classifications=classifications,
        explanation=(
            f"all of [{inner}] must be satisfied (AND); the most restrictive governs → {posture}"
        ),
    )


def _combine_or(children: list[_NodeEval]) -> _NodeEval:
    # Choose the most permissive option, breaking ties by original order.
    best_index, best = min(
        enumerate(children), key=lambda pair: (POSTURE_SEVERITY[pair[1].posture], pair[0])
    )
    posture = best.posture
    # Under OR you comply with the option you choose, so obligations follow it.
    obligations = best.obligations
    rule_ids = _dedupe(tuple(r for c in children for r in c.rule_ids))
    classifications = tuple(s for c in children for s in c.classifications)
    inner = ", ".join(c.explanation for c in children)
    chosen = best.classifications[0].license_key if best.classifications else "selected option"
    return _NodeEval(
        posture=posture,
        obligations=obligations,
        rule_ids=rule_ids,
        classifications=classifications,
        explanation=(
            f"a choice of [{inner}] (OR); the most permissive may be selected "
            f"→ choose {chosen} → {posture}"
        ),
    )


def _eval_node(node: Any, policy: Policy) -> _NodeEval:
    if isinstance(node, le.LicenseWithExceptionSymbol):
        return _eval_with(node, policy)
    if isinstance(node, le.LicenseSymbol):
        return _eval_symbol(node, policy)
    if isinstance(node, le.AND):
        return _combine_and([_eval_node(arg, policy) for arg in node.args])
    if isinstance(node, le.OR):
        return _combine_or([_eval_node(arg, policy) for arg in node.args])
    # Defensive: an unexpected node type is treated as unresolved.
    sc = policy.unresolved_classification(str(node), "unrecognised licence-expression structure")
    return _NodeEval(sc.posture, sc.obligations, (sc.rule_id,), (sc,), sc.note or "unresolved")


def classify_component(
    component: Component, policy: Policy, exceptions: ExceptionSet | None = None
) -> ComponentResult:
    """Classify a single component, applying any project exception afterwards."""
    exceptions = exceptions or empty_exception_set()
    resolution = resolve(component.licenses)

    if resolution.unresolved or resolution.expression is None:
        key = resolution.normalized or "(no licence identified)"
        reason = resolution.unresolved_reason or "licence could not be resolved"
        sc = policy.unresolved_classification(key, reason)
        base_posture = sc.posture
        explanation = (
            f"Unresolved: {reason}. Conservative default posture '{base_posture}' applied "
            f"(policy category '{policy.unresolved_category}')."
        )
        classifications = (sc,)
        obligations = sc.obligations
        rule_ids = (sc.rule_id,)
        unresolved = True
    else:
        node_eval = _eval_node(resolution.expression, policy)
        base_posture = node_eval.posture
        explanation = (
            f"Resolved SPDX expression '{resolution.normalized}' "
            f"(from {resolution.source} licence information): {node_eval.explanation}."
        )
        classifications = node_eval.classifications
        obligations = node_eval.obligations
        rule_ids = _dedupe(node_eval.rule_ids)
        unresolved = False

    applied: AppliedException | None = None
    rule = exceptions.find(component.name, component.version)
    if rule is not None:
        applied = AppliedException(
            component=component.name,
            version=component.version or "(unspecified)",
            override_posture=rule.posture,
            original_posture=base_posture,
            justification=rule.justification,
            owner=rule.owner,
            date=rule.date,
        )

    return ComponentResult(
        component=component,
        normalized_expression=resolution.normalized,
        license_source=resolution.source,
        symbol_classifications=classifications,
        base_posture=base_posture,
        posture_explanation=explanation,
        unresolved=unresolved,
        unresolved_reason=resolution.unresolved_reason if unresolved else None,
        obligations=obligations,
        rule_ids=rule_ids,
        exception=applied,
    )


def _count(results: tuple[ComponentResult, ...]) -> Counts:
    allowed = sum(1 for r in results if r.final_posture == "allowed")
    review = sum(1 for r in results if r.final_posture == "review")
    blocked = sum(1 for r in results if r.final_posture == "blocked")
    unresolved = sum(1 for r in results if r.unresolved)
    exceptions_applied = sum(1 for r in results if r.exception is not None)
    return Counts(
        total=len(results),
        allowed=allowed,
        review=review,
        blocked=blocked,
        unresolved=unresolved,
        exceptions_applied=exceptions_applied,
    )


def analyze(
    sbom: Sbom,
    policy: Policy,
    exceptions: ExceptionSet | None = None,
    *,
    tool_name: str = DEFAULT_TOOL_NAME,
    tool_version: str = __version__,
    gate_fail_on: tuple[Posture, ...] = (),
) -> AnalysisResult:
    """Run the full classification pipeline over an SBOM."""
    exceptions = exceptions or empty_exception_set()
    results = tuple(classify_component(c, policy, exceptions) for c in sbom.components)
    overall: Posture = reduce(worse, (r.final_posture for r in results), POSTURE_ALLOWED)
    return AnalysisResult(
        sbom=sbom,
        policy=policy.meta,
        results=results,
        overall_posture=overall,
        counts=_count(results),
        tool_name=tool_name,
        tool_version=tool_version,
        exceptions_source=exceptions.source_path,
        gate_fail_on=tuple(gate_fail_on),
    )
