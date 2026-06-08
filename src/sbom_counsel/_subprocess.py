"""Small subprocess helper shared by the optional SBOM-acquisition wrappers.

Used by the cargo and Syft convenience paths. The runner type is injectable so
those paths can be tested without the external tools installed. The core analysis
never uses this module — acquisition is always an optional, separate step.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from .errors import EnvironmentToolError

# A runner takes (args, cwd) and returns captured stdout, or raises.
Runner = Callable[[list[str], Path], str]


def run_tool(args: list[str], cwd: Path) -> str:
    """Run an external tool, returning stdout or raising EnvironmentToolError."""
    executable = args[0]
    if shutil.which(executable) is None:
        raise EnvironmentToolError(
            f"Required tool '{executable}' was not found on PATH.",
            hint=f"Install {executable}, or supply an SBOM and use 'analyze' instead.",
        )
    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:  # pragma: no cover - environment dependent
        raise EnvironmentToolError(f"Could not run {' '.join(args)}: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no output"
        raise EnvironmentToolError(
            f"{' '.join(args)} failed (exit {completed.returncode}): {detail}",
        )
    return completed.stdout
