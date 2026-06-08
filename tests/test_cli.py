"""End-to-end CLI tests, including exit-code behaviour."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from sbom_counsel.cli import main

CLEAN_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "type": "library",
            "name": "a",
            "version": "1.0.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
        {
            "type": "library",
            "name": "b",
            "version": "2.0.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
        },
    ],
}


def _write(path: Path, data: dict[str, Any]) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_version() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_analyze_writes_all_outputs(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "clean.cdx.json", CLEAN_SBOM)
    out = tmp_path / "report"
    result = CliRunner().invoke(main, ["analyze", str(sbom), "-o", str(out)])
    assert result.exit_code == 0
    for name in ("report.json", "report.md", "report.html", "notices.txt", "notices.md"):
        assert (out / name).is_file()


def test_clean_sbom_gate_passes(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "clean.cdx.json", CLEAN_SBOM)
    result = CliRunner().invoke(main, ["analyze", str(sbom), "-o", str(tmp_path / "r"), "--gate"])
    assert result.exit_code == 0
    assert "passed" in result.output


def test_gate_fails_on_blocked(cyclonedx_hardcases_path: Path, tmp_path: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["analyze", str(cyclonedx_hardcases_path), "-o", str(tmp_path / "r"), "--gate"],
    )
    assert result.exit_code == 1
    assert "FAILED" in result.output


def test_gate_fail_on_review(tmp_path: Path) -> None:
    # A single unresolved component is 'review'; --fail-on review must trip.
    sbom = _write(
        tmp_path / "x.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "x", "version": "1.0.0"}],
        },
    )
    result = CliRunner().invoke(
        main,
        ["analyze", str(sbom), "-o", str(tmp_path / "r"), "--gate", "--fail-on", "review"],
    )
    assert result.exit_code == 1


def test_print_json_to_stdout_writes_no_files(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "clean.cdx.json", CLEAN_SBOM)
    out = tmp_path / "should-not-exist"
    result = CliRunner().invoke(main, ["analyze", str(sbom), "-o", str(out), "--print", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["summary"]["overall_posture"] == "allowed"
    assert not out.exists()


def test_strict_unresolved_blocks(tmp_path: Path) -> None:
    sbom = _write(
        tmp_path / "x.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [{"type": "library", "name": "x", "version": "1.0.0"}],
        },
    )
    result = CliRunner().invoke(
        main, ["analyze", str(sbom), "--print", "json", "--strict-unresolved"]
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["summary"]["overall_posture"] == "blocked"


def test_format_selection_writes_only_requested(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "clean.cdx.json", CLEAN_SBOM)
    out = tmp_path / "report"
    result = CliRunner().invoke(main, ["analyze", str(sbom), "-o", str(out), "--format", "md"])
    assert result.exit_code == 0
    assert (out / "report.md").is_file()
    assert not (out / "report.html").exists()
    assert not (out / "report.json").exists()


def test_missing_file_exit_3(tmp_path: Path) -> None:
    result = CliRunner().invoke(main, ["analyze", str(tmp_path / "nope.json")])
    assert result.exit_code == 3
    assert "not found" in result.output


def test_bad_policy_exit_4(tmp_path: Path) -> None:
    sbom = _write(tmp_path / "clean.cdx.json", CLEAN_SBOM)
    bad = tmp_path / "bad.yaml"
    bad.write_text("categories: {permissive: {posture: nonsense}}", encoding="utf-8")
    result = CliRunner().invoke(
        main, ["analyze", str(sbom), "--policy", str(bad), "--print", "json"]
    )
    assert result.exit_code == 4


def test_exceptions_applied_via_cli(cyclonedx_hardcases_path: Path, tmp_path: Path) -> None:
    exc = tmp_path / "exc.yaml"
    exc.write_text(
        "exceptions:\n"
        "  - component: agpl-lib\n"
        "    version: '1.0.0'\n"
        "    posture: allowed\n"
        "    justification: Not distributed; server-side internal tool only.\n"
        "    owner: GC\n"
        "    date: 2026-01-01\n",
        encoding="utf-8",
    )
    result = CliRunner().invoke(
        main,
        ["analyze", str(cyclonedx_hardcases_path), "--exceptions", str(exc), "--print", "json"],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["summary"]["counts"]["exceptions_applied"] == 1


def test_init_policy_and_exceptions() -> None:
    runner = CliRunner()
    policy = runner.invoke(main, ["init-policy"])
    assert policy.exit_code == 0
    assert "categories:" in policy.output
    exceptions = runner.invoke(main, ["init-exceptions"])
    assert exceptions.exit_code == 0
    assert "exceptions:" in exceptions.output


def test_init_to_file(tmp_path: Path) -> None:
    runner = CliRunner()
    policy_file = tmp_path / "p.yaml"
    exc_file = tmp_path / "e.yaml"
    assert runner.invoke(main, ["init-policy", "-o", str(policy_file)]).exit_code == 0
    assert runner.invoke(main, ["init-exceptions", "-o", str(exc_file)]).exit_code == 0
    assert "categories:" in policy_file.read_text(encoding="utf-8")
    assert "exceptions:" in exc_file.read_text(encoding="utf-8")
    # The written policy and exceptions are valid and usable together.
    sbom = _write(tmp_path / "clean.cdx.json", CLEAN_SBOM)
    result = CliRunner().invoke(
        main,
        ["analyze", str(sbom), "--policy", str(policy_file), "--print", "json"],
    )
    assert result.exit_code == 0


def test_include_vulnerabilities_flag(cyclonedx_hardcases_path: Path) -> None:
    # Without --gate the run succeeds (exit 0) even with blocked components.
    result = CliRunner().invoke(
        main,
        ["analyze", str(cyclonedx_hardcases_path), "--print", "json", "--include-vulnerabilities"],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "vulnerabilities" in parsed
