"""Optional convenience: generate an SBOM from a project with Syft, then analyse.

`Syft <https://github.com/anchore/syft>`_ scans a directory, a lockfile, or a
container image across many ecosystems and emits CycloneDX or SPDX. Wrapping it
lets a user who does not already have an SBOM still get started with one command.

This is an optional, clearly separated step: the SBOM path remains the primary,
ecosystem-agnostic route, and the core analysis never shells out. The runner is
injectable so this module can be tested without Syft installed.
"""

from __future__ import annotations

import json
from pathlib import Path

from ._subprocess import Runner, run_tool
from .errors import EnvironmentToolError, InputError
from .ingest import parse_sbom
from .models import Sbom


def sbom_from_syft(target: str | Path, *, runner: Runner = run_tool) -> Sbom:
    """Run Syft against ``target`` to produce a CycloneDX SBOM and normalise it."""
    path = Path(target)
    if not path.exists():
        raise EnvironmentToolError(
            f"Scan target not found: {path}",
            hint="Point the scan target at a project directory, a lockfile, or an archive.",
        )

    cwd = path if path.is_dir() else path.parent
    raw = runner(["syft", str(path), "-o", "cyclonedx-json"], cwd)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise EnvironmentToolError(f"Could not parse Syft output as JSON: {exc}") from exc

    try:
        sbom = parse_sbom(data, f"syft:{path}")
    except InputError as exc:
        raise EnvironmentToolError(
            f"Syft produced output this tool could not read: {exc}",
        ) from exc
    return sbom
