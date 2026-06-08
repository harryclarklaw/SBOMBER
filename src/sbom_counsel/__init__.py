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

__all__ = ["APP_NAME", "APP_TAGLINE", "__version__"]
