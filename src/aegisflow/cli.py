"""Command-line workflows for local AegisFlow development."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from aegisflow.db.session import create_db_engine
from aegisflow.services.imports import ImportSummary, import_semgrep_report

app = typer.Typer(
    help="Import security scanner reports into AegisFlow.",
    no_args_is_help=True,
)

@app.callback()
def main() -> None:
    """Provide a root command so AegisFlow keeps explicit subcommands."""

@app.command("import-semgrep")
def import_semgrep(
    report_path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to a Semgrep JSON report.",
    ),
    repository: str = typer.Option(
        ...,
        "--repository",
        help="Repository full name, for example demo/vulnerable-service.",
    ),
    commit_sha: str = typer.Option(
        ...,
        "--commit",
        help="Commit SHA associated with the scanner report.",
    ),
) -> None:
    """Load one Semgrep JSON report and import it atomically."""

    try:
        report = load_json_report(report_path)
        engine = create_db_engine()
        try:
            summary = import_semgrep_report(
                engine=engine,
                report=report,
                repository_full_name=repository,
                commit_sha=commit_sha,
            )
        finally:
            engine.dispose()
    except (OSError, TypeError, ValueError) as error:
        typer.echo(f"Import failed: {error}", err=True)
        raise typer.Exit(code=2)

    print_import_summary(summary)


def load_json_report(report_path: Path) -> dict[str, Any]:
    """Read one JSON object from disk for the CLI boundary."""

    try:
        raw_value = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"'{report_path}' is not valid JSON: {error.msg}"
        ) from error

    if not isinstance(raw_value, dict):
        raise TypeError(f"'{report_path}' must contain a JSON object")
    return raw_value


def print_import_summary(summary: ImportSummary) -> None:
    """Print a concise result suitable for local use and future CI logs."""

    typer.echo("Import complete")
    typer.echo(f"  scan run: {summary.scan_run_id}")
    typer.echo(f"  created findings: {summary.created_findings}")
    typer.echo(f"  reused findings: {summary.reused_findings}")
    typer.echo(f"  observations created: {summary.observations_created}")