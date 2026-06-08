"""Convenience wrapper to derive component data from a Rust project.

This is a secondary, convenience path. The primary, ecosystem-agnostic route is
an SBOM file. Here we shell out to Rust tooling already present on the system to
collect components, then feed them into the same analysis pipeline.

Two sources are supported:

* ``cargo-metadata`` (default) — ``cargo metadata`` is part of cargo itself and
  reports each package's SPDX ``license`` expression. This is the reliable path.
* ``cargo-deny`` — parsed best-effort from ``cargo deny list`` JSON when that
  tool is installed.

The command runner is injectable so the parsing can be tested without the tools
installed. Network is never used: cargo runs against the local project only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .errors import EnvironmentToolError
from .models import Component, LicenseFinding, Sbom

# A runner takes (args, cwd) and returns captured stdout, or raises.
Runner = Callable[[list[str], Path], str]


def _default_runner(args: list[str], cwd: Path) -> str:
    executable = args[0]
    if shutil.which(executable) is None:
        raise EnvironmentToolError(
            f"Required tool '{executable}' was not found on PATH.",
            hint=f"Install {executable}, or use the SBOM path (analyze) instead.",
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


def _authors_to_str(authors: Any) -> str | None:
    if isinstance(authors, list):
        names = [a for a in authors if isinstance(a, str) and a.strip()]
        if names:
            return ", ".join(name.strip() for name in names)
    if isinstance(authors, str) and authors.strip():
        return authors.strip()
    return None


def components_from_cargo_metadata(metadata: dict[str, Any]) -> tuple[Component, ...]:
    """Convert ``cargo metadata`` JSON into components (excluding workspace crates)."""
    workspace = set(metadata.get("workspace_members") or [])
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        return ()
    components: list[Component] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        if package.get("id") in workspace:
            continue  # the project's own crate(s), not a third-party dependency
        name = package.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        version = package.get("version") if isinstance(package.get("version"), str) else None
        license_expr = package.get("license")
        findings: tuple[LicenseFinding, ...] = ()
        if isinstance(license_expr, str) and license_expr.strip():
            # cargo uses '/' as a historical separator for OR; normalise it.
            normalised = license_expr.replace("/", " OR ").strip()
            findings = (LicenseFinding(raw=normalised, kind="expression", source="declared"),)
        repository = package.get("repository")
        purl = f"pkg:cargo/{name}@{version}" if version else f"pkg:cargo/{name}"
        components.append(
            Component(
                name=name.strip(),
                version=version,
                author=_authors_to_str(package.get("authors")),
                purl=purl,
                homepage=repository if isinstance(repository, str) else None,
                licenses=findings,
            )
        )
    return tuple(components)


def _iter_cargo_deny_crates(data: Any) -> list[dict[str, Any]]:
    """Yield crate-like dicts from the various shapes cargo-deny list can emit."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        # Crate-layout often maps "name version" -> info, or name -> info.
        crates: list[dict[str, Any]] = []
        for key, value in data.items():
            if isinstance(value, dict):
                merged = {"_key": key, **value}
                crates.append(merged)
        return crates
    return []


def components_from_cargo_deny(data: Any) -> tuple[Component, ...]:
    """Best-effort conversion of ``cargo deny list`` JSON into components.

    Tolerant of key naming differences across cargo-deny versions: it looks for a
    crate name, version, and licence expression under several plausible keys.
    """
    components: list[Component] = []
    for crate in _iter_cargo_deny_crates(data):
        name = crate.get("name")
        if not isinstance(name, str) and isinstance(crate.get("_key"), str):
            # Keys are often "name version".
            name = crate["_key"].split(" ")[0]
        if not isinstance(name, str) or not name.strip():
            continue
        version = crate.get("version")
        if not isinstance(version, str) and isinstance(crate.get("_key"), str):
            parts = crate["_key"].split(" ")
            version = parts[1] if len(parts) > 1 else None
        license_expr = crate.get("license") or crate.get("spdx") or crate.get("licenses")
        if isinstance(license_expr, list):
            license_expr = " AND ".join(str(item) for item in license_expr)
        findings: tuple[LicenseFinding, ...] = ()
        if isinstance(license_expr, str) and license_expr.strip():
            findings = (
                LicenseFinding(raw=license_expr.strip(), kind="expression", source="declared"),
            )
        purl = f"pkg:cargo/{name}@{version}" if isinstance(version, str) else f"pkg:cargo/{name}"
        components.append(
            Component(
                name=name.strip(),
                version=version if isinstance(version, str) else None,
                purl=purl,
                licenses=findings,
            )
        )
    return tuple(components)


def collect_sbom(
    project_dir: str | Path,
    *,
    tool: str = "auto",
    runner: Runner = _default_runner,
) -> Sbom:
    """Collect components from a Rust project directory and wrap them as an Sbom."""
    directory = Path(project_dir)
    if not directory.is_dir():
        raise EnvironmentToolError(f"Project directory not found: {directory}")
    if not (directory / "Cargo.toml").is_file():
        raise EnvironmentToolError(
            f"No Cargo.toml found in {directory}.",
            hint="Point --project at a Rust crate or workspace root.",
        )

    chosen = tool
    if chosen == "auto":
        chosen = "cargo-deny" if shutil.which("cargo-deny") else "cargo-metadata"

    if chosen == "cargo-metadata":
        raw = runner(["cargo", "metadata", "--format-version", "1", "--locked"], directory)
        try:
            metadata = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EnvironmentToolError(f"Could not parse cargo metadata output: {exc}") from exc
        components = components_from_cargo_metadata(metadata)
        source_format = "cargo-metadata"
    elif chosen == "cargo-deny":
        raw = runner(["cargo", "deny", "list", "--layout", "crate", "--format", "json"], directory)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EnvironmentToolError(f"Could not parse cargo-deny output: {exc}") from exc
        components = components_from_cargo_deny(data)
        source_format = "cargo-deny"
    else:
        raise EnvironmentToolError(f"Unknown cargo tool: {tool!r}")

    return Sbom(
        sbom_format=source_format,  # type: ignore[arg-type]
        spec_version="n/a",
        components=components,
        document_name=directory.resolve().name,
        source_path=str(directory),
    )
