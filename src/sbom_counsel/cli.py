"""Command-line interface.

Two personas are served: a lawyer reading the report, and an engineer running
the tool as a CI gate. The lawyer gets readable Markdown/HTML; the engineer gets
JSON and meaningful exit codes (0 = success, 1 = gate failed, 3 = input error,
4 = config error, 5 = environment error).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Any

import click

from . import APP_NAME, APP_TAGLINE, __version__
from . import cargo as cargo_mod
from .classify import analyze
from .errors import ExitCode, SbomCounselError
from .ingest import load_sbom
from .models import AnalysisResult, Posture
from .policy import (
    Policy,
    default_policy_text,
    load_default_policy,
    load_exceptions,
    load_policy,
)
from .report import (
    build_report_data,
    render_html,
    render_json,
    render_markdown,
    render_notices_markdown,
    render_notices_text,
)

_POSTURE_COLOUR = {"allowed": "green", "review": "yellow", "blocked": "red"}

_EXCEPTIONS_TEMPLATE = """\
# sbom-counsel exceptions file
#
# Each exception overrides the posture for one component (and version). Every
# exception MUST carry a justification, an owner, and a date, or it is rejected.
# Applied exceptions are recorded in the report for audit.
exceptions:
  - component: example-lib       # component name as it appears in the SBOM
    version: "1.2.3"             # exact version, or "*" for any version
    posture: allowed             # allowed | review | blocked
    justification: >-
      Why this override is justified (e.g. build-time-only dependency that is not
      distributed in the shipped product).
    owner: Name of the approver
    date: 2026-01-01             # ISO date (YYYY-MM-DD)
"""


def _handle_errors(func: Callable[..., Any]) -> Callable[..., Any]:
    """Convert expected errors into clean messages and exit codes, no traceback."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        show_traceback = bool(kwargs.get("traceback"))
        try:
            return func(*args, **kwargs)
        except SbomCounselError as err:
            click.secho(f"error: {err}", fg="red", err=True)
            raise SystemExit(int(err.exit_code)) from None
        except (click.ClickException, click.exceptions.Exit, SystemExit):
            raise
        except Exception as err:  # noqa: BLE001 - top-level safety net
            if show_traceback:
                raise
            click.secho(f"internal error: {err}", fg="red", err=True)
            click.secho(
                "This was unexpected. Re-run with --traceback to see details, "
                "and please report it.",
                err=True,
            )
            raise SystemExit(int(ExitCode.INTERNAL_ERROR)) from None

    return wrapper


def _load_policy(policy_path: Path | None, *, strict_unresolved: bool) -> Policy:
    policy = load_policy(policy_path) if policy_path is not None else load_default_policy()
    if strict_unresolved:
        policy = policy.with_unresolved_posture("blocked")
    return policy


def _gate_fail_on(gate: bool, fail_on: str) -> tuple[Posture, ...]:
    if not gate:
        return ()
    if fail_on == "review":
        return ("review", "blocked")
    return ("blocked",)


def _render_selected(
    result: AnalysisResult, formats: tuple[str, ...], include_vulnerabilities: bool
) -> dict[str, str]:
    data = build_report_data(result, include_vulnerabilities=include_vulnerabilities)
    builders: dict[str, Callable[[], str]] = {
        "report.json": lambda: render_json(data),
        "report.md": lambda: render_markdown(data),
        "report.html": lambda: render_html(data),
        "notices.txt": lambda: render_notices_text(result),
        "notices.md": lambda: render_notices_markdown(result),
    }
    selected: list[str] = []
    fmts = set(formats)
    if "all" in fmts:
        selected = list(builders)
    else:
        if "json" in fmts:
            selected.append("report.json")
        if "md" in fmts:
            selected.append("report.md")
        if "html" in fmts:
            selected.append("report.html")
        if "notices" in fmts:
            selected.extend(["notices.txt", "notices.md"])
    return {name: builders[name]() for name in selected}


def _print_one(result: AnalysisResult, print_format: str, include_vulnerabilities: bool) -> None:
    data = build_report_data(result, include_vulnerabilities=include_vulnerabilities)
    rendered = {
        "json": lambda: render_json(data),
        "md": lambda: render_markdown(data),
        "html": lambda: render_html(data),
        "notices-txt": lambda: render_notices_text(result),
        "notices-md": lambda: render_notices_markdown(result),
    }[print_format]()
    click.echo(rendered, nl=False)


def _print_summary(result: AnalysisResult, written: dict[str, Path]) -> None:
    counts = result.counts
    posture = result.overall_posture
    click.echo("")
    click.secho(
        f"Overall release posture: {posture.upper()}",
        fg=_POSTURE_COLOUR.get(posture),
        bold=True,
    )
    click.echo(
        f"Policy: {result.policy.name} (v{result.policy.version}); "
        f"SBOM: {result.sbom.document_name or result.sbom.source_path or 'input'} "
        f"({result.sbom.sbom_format})."
    )
    click.echo(
        f"  blocked: {counts.blocked}   review: {counts.review}   "
        f"allowed: {counts.allowed}   (unresolved: {counts.unresolved}, "
        f"exceptions: {counts.exceptions_applied}, total: {counts.total})"
    )
    if result.gate_fail_on:
        if result.gate_failed:
            click.secho(
                f"  gate: FAILED (fails on {', '.join(result.gate_fail_on)})",
                fg="red",
                bold=True,
            )
        else:
            click.secho("  gate: passed", fg="green")
    if written:
        click.echo("  written:")
        for _name, path in written.items():
            click.echo(f"    - {path}")


def _emit(
    result: AnalysisResult,
    *,
    output_dir: Path,
    formats: tuple[str, ...],
    include_vulnerabilities: bool,
    print_format: str | None,
    quiet: bool,
) -> int:
    if print_format is not None:
        _print_one(result, print_format, include_vulnerabilities)
    else:
        outputs = _render_selected(result, formats, include_vulnerabilities)
        written: dict[str, Path] = {}
        output_dir.mkdir(parents=True, exist_ok=True)
        for name, content in outputs.items():
            path = output_dir / name
            path.write_text(content, encoding="utf-8")
            written[name] = path
        if not quiet:
            _print_summary(result, written)
    return int(ExitCode.GATE_FAILED) if result.gate_failed else int(ExitCode.SUCCESS)


# --- Shared options ----------------------------------------------------------


def _analysis_options(func: Callable[..., Any]) -> Callable[..., Any]:
    options = [
        click.option(
            "--policy",
            "policy_path",
            type=click.Path(path_type=Path, dir_okay=False),
            default=None,
            help="Policy YAML file. Defaults to the built-in conservative policy.",
        ),
        click.option(
            "--exceptions",
            "exceptions_path",
            type=click.Path(path_type=Path, dir_okay=False),
            default=None,
            help="Project exceptions YAML file (optional).",
        ),
        click.option(
            "--output-dir",
            "-o",
            "output_dir",
            type=click.Path(path_type=Path, file_okay=False),
            default=Path("sbom-counsel-report"),
            show_default=True,
            help="Directory for the generated report files.",
        ),
        click.option(
            "--format",
            "formats",
            type=click.Choice(["all", "json", "md", "html", "notices"]),
            multiple=True,
            default=("all",),
            show_default=True,
            help="Which outputs to write (repeatable).",
        ),
        click.option(
            "--print",
            "print_format",
            type=click.Choice(["json", "md", "html", "notices-txt", "notices-md"]),
            default=None,
            help="Print one rendered output to stdout instead of writing files.",
        ),
        click.option("--gate", is_flag=True, default=False, help="Enable CI gate (exit code)."),
        click.option(
            "--fail-on",
            type=click.Choice(["blocked", "review"]),
            default="blocked",
            show_default=True,
            help="Gate threshold: fail on 'blocked', or also on 'review'.",
        ),
        click.option(
            "--strict-unresolved",
            is_flag=True,
            default=False,
            help="Treat unresolved/unknown licences as 'blocked' regardless of policy.",
        ),
        click.option(
            "--include-vulnerabilities",
            is_flag=True,
            default=False,
            help="Include any vulnerability data already present in the SBOM.",
        ),
        click.option("--quiet", is_flag=True, default=False, help="Suppress the summary."),
        click.option(
            "--traceback",
            is_flag=True,
            default=False,
            hidden=True,
            help="Show a full traceback on unexpected errors.",
        ),
    ]
    for option in reversed(options):
        func = option(func)
    return func


# --- Commands ----------------------------------------------------------------


@click.group(help=f"{APP_NAME}: {APP_TAGLINE}.")
@click.version_option(__version__, prog_name=APP_NAME)
def main() -> None:
    pass


@main.command(name="analyze", help="Analyse a CycloneDX or SPDX SBOM file.")
@click.argument("sbom_path", type=click.Path(path_type=Path, dir_okay=False))
@_analysis_options
@_handle_errors
def analyze_cmd(
    sbom_path: Path,
    policy_path: Path | None,
    exceptions_path: Path | None,
    output_dir: Path,
    formats: tuple[str, ...],
    print_format: str | None,
    gate: bool,
    fail_on: str,
    strict_unresolved: bool,
    include_vulnerabilities: bool,
    quiet: bool,
    traceback: bool,
) -> None:
    sbom = load_sbom(sbom_path)
    policy = _load_policy(policy_path, strict_unresolved=strict_unresolved)
    exceptions = load_exceptions(exceptions_path) if exceptions_path is not None else None
    result = analyze(
        sbom,
        policy,
        exceptions,
        tool_name=APP_NAME,
        tool_version=__version__,
        gate_fail_on=_gate_fail_on(gate, fail_on),
    )
    code = _emit(
        result,
        output_dir=output_dir,
        formats=formats,
        include_vulnerabilities=include_vulnerabilities,
        print_format=print_format,
        quiet=quiet,
    )
    raise SystemExit(code)


@main.command(name="cargo", help="Convenience: analyse a Rust project via cargo tooling.")
@click.argument("project_dir", type=click.Path(path_type=Path, file_okay=False))
@click.option(
    "--tool",
    type=click.Choice(["auto", "cargo-metadata", "cargo-deny"]),
    default="auto",
    show_default=True,
    help="Which cargo tool to source component data from.",
)
@_analysis_options
@_handle_errors
def cargo_cmd(
    project_dir: Path,
    tool: str,
    policy_path: Path | None,
    exceptions_path: Path | None,
    output_dir: Path,
    formats: tuple[str, ...],
    print_format: str | None,
    gate: bool,
    fail_on: str,
    strict_unresolved: bool,
    include_vulnerabilities: bool,
    quiet: bool,
    traceback: bool,
) -> None:
    sbom = cargo_mod.collect_sbom(project_dir, tool=tool)
    policy = _load_policy(policy_path, strict_unresolved=strict_unresolved)
    exceptions = load_exceptions(exceptions_path) if exceptions_path is not None else None
    result = analyze(
        sbom,
        policy,
        exceptions,
        tool_name=APP_NAME,
        tool_version=__version__,
        gate_fail_on=_gate_fail_on(gate, fail_on),
    )
    code = _emit(
        result,
        output_dir=output_dir,
        formats=formats,
        include_vulnerabilities=include_vulnerabilities,
        print_format=print_format,
        quiet=quiet,
    )
    raise SystemExit(code)


@main.command(name="init-policy", help="Write the default policy to stdout (or a file).")
@click.option(
    "--output",
    "-o",
    "output",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Write to this file instead of stdout.",
)
@_handle_errors
def init_policy_cmd(output: Path | None) -> None:
    text = default_policy_text()
    if output is None:
        click.echo(text, nl=False)
    else:
        output.write_text(text, encoding="utf-8")
        click.echo(f"Wrote default policy to {output}")


@main.command(name="init-exceptions", help="Write a starter exceptions file to stdout (or a file).")
@click.option(
    "--output",
    "-o",
    "output",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Write to this file instead of stdout.",
)
@_handle_errors
def init_exceptions_cmd(output: Path | None) -> None:
    if output is None:
        click.echo(_EXCEPTIONS_TEMPLATE, nl=False)
    else:
        output.write_text(_EXCEPTIONS_TEMPLATE, encoding="utf-8")
        click.echo(f"Wrote starter exceptions file to {output}")


if __name__ == "__main__":  # pragma: no cover
    main()
