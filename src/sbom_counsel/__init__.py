"""sbom-counsel: open-source licence-risk analysis for software bills of materials.

This package ingests a CycloneDX or SPDX SBOM, classifies every component's
licence against an external, lawyer-editable policy, applies project exceptions,
and renders a lawyer-readable risk report plus a third-party attribution notices
file. It runs fully offline and produces deterministic output.

The display name of the tool is defined once here (``APP_NAME``) so the product
can be renamed without touching the rest of the source. The console command and
the importable module name are set in ``pyproject.toml``.
"""

from __future__ import annotations

__version__ = "0.1.0"

# Single source of truth for the user-facing product name. Change this to
# rename the tool everywhere it appears in reports and help text. (The console
# script name and the Python import name live in pyproject.toml.)
APP_NAME = "sbom-counsel"

# One-line description reused in report headers and help text.
APP_TAGLINE = "Open-source licence-risk analysis for software bills of materials"

# Public library API. Imported after the constants above so that submodules which
# read these constants at import time do not see a partially-initialised package.
from .classify import analyze, classify_component  # noqa: E402
from .ingest import load_sbom, parse_sbom  # noqa: E402
from .models import AnalysisResult, ComponentResult, Sbom  # noqa: E402
from .policy import (  # noqa: E402
    load_default_policy,
    load_exceptions,
    load_policy,
)
from .report import build_report_data, render_all  # noqa: E402
from .webapi import analyze_text, analyze_text_json  # noqa: E402

__all__ = [
    "APP_NAME",
    "APP_TAGLINE",
    "AnalysisResult",
    "ComponentResult",
    "Sbom",
    "__version__",
    "analyze",
    "analyze_text",
    "analyze_text_json",
    "build_report_data",
    "classify_component",
    "load_default_policy",
    "load_exceptions",
    "load_policy",
    "load_sbom",
    "parse_sbom",
    "render_all",
]
