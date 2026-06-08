"""Normalised internal data model and analysis result types.

These dataclasses are the contract between the layers of the tool: ingestion
produces a :class:`Sbom` of :class:`Component` objects; classification produces
:class:`ComponentResult` objects collected into an :class:`AnalysisResult`; the
reporting layer renders that result. Everything is frozen and uses tuples rather
than lists so results are immutable and ordering is explicit and deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# --- Ship postures -----------------------------------------------------------
# A posture answers: can a component carrying this licence be shipped in a
# proprietary, commercially distributed product? Severity increases left to
# right. Uncertainty must always resolve towards a higher severity, never lower.
Posture = Literal["allowed", "review", "blocked"]

POSTURE_ALLOWED: Posture = "allowed"
POSTURE_REVIEW: Posture = "review"
POSTURE_BLOCKED: Posture = "blocked"

ALL_POSTURES: tuple[Posture, ...] = (POSTURE_ALLOWED, POSTURE_REVIEW, POSTURE_BLOCKED)

# Higher number = more severe / more restrictive.
POSTURE_SEVERITY: dict[Posture, int] = {
    POSTURE_ALLOWED: 0,
    POSTURE_REVIEW: 1,
    POSTURE_BLOCKED: 2,
}


def worse(a: Posture, b: Posture) -> Posture:
    """Return the more severe of two postures (used for AND and for overall)."""
    return a if POSTURE_SEVERITY[a] >= POSTURE_SEVERITY[b] else b


def better(a: Posture, b: Posture) -> Posture:
    """Return the less severe of two postures (used for OR / dual licensing)."""
    return a if POSTURE_SEVERITY[a] <= POSTURE_SEVERITY[b] else b


# --- Ingestion model ---------------------------------------------------------

SbomFormat = Literal["cyclonedx", "spdx"]

# Where a licence statement was found, in order of authority.
LicenseSource = Literal["concluded", "declared"]


@dataclass(frozen=True)
class Hash:
    """A content hash recorded for a component."""

    algorithm: str
    value: str


@dataclass(frozen=True)
class EmbeddedLicenseText:
    """Licence text carried inside the SBOM itself.

    Used verbatim in the notices file. The tool never invents licence text; it
    only reproduces text that is present in the SBOM or in its bundled, verbatim
    SPDX licence-text store.
    """

    license_id: str | None
    name: str | None
    text: str


@dataclass(frozen=True)
class Vulnerability:
    """Optional vulnerability data carried by the SBOM.

    The tool does not generate this; it only surfaces it when present and when
    the user opts in. It is kept entirely separate from licence analysis.
    """

    id: str
    source: str | None = None
    severity: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class LicenseFinding:
    """A single raw licence statement found for a component, before resolution.

    ``raw`` is exactly what the SBOM said (an SPDX id, an SPDX expression, or a
    free-text name). ``kind`` records how the SBOM expressed it so resolution can
    treat an expression differently from a free-text name.
    """

    raw: str
    kind: Literal["id", "expression", "name"]
    source: LicenseSource


@dataclass(frozen=True)
class Component:
    """A single component in the normalised model."""

    name: str
    version: str | None = None
    supplier: str | None = None
    author: str | None = None
    purl: str | None = None
    bom_ref: str | None = None
    copyright: str | None = None
    homepage: str | None = None
    licenses: tuple[LicenseFinding, ...] = ()
    embedded_texts: tuple[EmbeddedLicenseText, ...] = ()
    hashes: tuple[Hash, ...] = ()
    vulnerabilities: tuple[Vulnerability, ...] = ()

    @property
    def display_version(self) -> str:
        return self.version if self.version else "(unspecified)"

    @property
    def identifier(self) -> str:
        """A stable, human-readable identifier used for deterministic sorting."""
        return self.purl or self.bom_ref or f"{self.name}@{self.display_version}"


@dataclass(frozen=True)
class Sbom:
    """A normalised SBOM: format metadata plus the component set."""

    sbom_format: SbomFormat
    spec_version: str
    components: tuple[Component, ...]
    document_name: str | None = None
    # Timestamp taken from the SBOM's own metadata (part of the input, so it is
    # deterministic). The tool never stamps reports with wall-clock time.
    metadata_timestamp: str | None = None
    source_path: str | None = None


# --- Classification result model --------------------------------------------


@dataclass(frozen=True)
class SymbolClassification:
    """The classification of a single licence symbol within an expression."""

    license_key: str  # Normalised SPDX id, or the raw token if not recognised.
    known: bool  # True if it is a recognised SPDX licence/exception id.
    category: str  # Policy category key, e.g. "permissive".
    posture: Posture
    rule_id: str  # Traceable id of the policy rule that produced this result.
    obligations: tuple[str, ...] = ()
    note: str | None = None


@dataclass(frozen=True)
class AppliedException:
    """Record of a project exception applied to a component."""

    component: str
    version: str
    override_posture: Posture
    original_posture: Posture
    justification: str
    owner: str
    date: str


@dataclass(frozen=True)
class ComponentResult:
    """The full, auditable classification result for one component."""

    component: Component
    normalized_expression: str | None
    license_source: LicenseSource | None
    symbol_classifications: tuple[SymbolClassification, ...]
    base_posture: Posture  # Posture from licence classification, before exception.
    posture_explanation: str
    unresolved: bool
    unresolved_reason: str | None
    obligations: tuple[str, ...]
    rule_ids: tuple[str, ...]
    exception: AppliedException | None = None

    @property
    def final_posture(self) -> Posture:
        """Posture after any exception override."""
        if self.exception is not None:
            return self.exception.override_posture
        return self.base_posture


@dataclass(frozen=True)
class PolicyMeta:
    """Identifying metadata about the policy that was applied."""

    name: str
    version: str
    description: str
    source_path: str | None = None


@dataclass(frozen=True)
class Counts:
    """Aggregate counts for the executive summary."""

    total: int
    allowed: int
    review: int
    blocked: int
    unresolved: int
    exceptions_applied: int


@dataclass(frozen=True)
class AnalysisResult:
    """The complete output of the analysis pipeline, ready for reporting."""

    sbom: Sbom
    policy: PolicyMeta
    results: tuple[ComponentResult, ...]
    overall_posture: Posture
    counts: Counts
    tool_name: str
    tool_version: str
    exceptions_source: str | None = None
    # Postures that the gate treats as failing, recorded for the report.
    gate_fail_on: tuple[Posture, ...] = field(default_factory=tuple)

    @property
    def gate_failed(self) -> bool:
        """Whether any component's final posture is in the gate's fail set."""
        if not self.gate_fail_on:
            return False
        fail = set(self.gate_fail_on)
        return any(r.final_posture in fail for r in self.results)
