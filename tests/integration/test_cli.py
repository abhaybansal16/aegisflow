from pathlib import Path

from sqlalchemy import text
from typer.testing import CliRunner

from aegisflow.cli import app
from aegisflow.db.session import create_db_engine

FIXTURE_PATH = Path("tests/fixtures/semgrep_report.json")
runner = CliRunner()


def clear_aegisflow_tables() -> None:
    """Keep the CLI import test independent in the local development database."""

    engine = create_db_engine()
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "TRUNCATE TABLE observations, scan_runs, findings, repositories CASCADE"
                )
            )
    finally:
        engine.dispose()


def test_import_semgrep_command_imports_fixture() -> None:
    clear_aegisflow_tables()

    result = runner.invoke(
        app,
        [
            "import-semgrep",
            str(FIXTURE_PATH),
            "--repository",
            "demo/vulnerable-service",
            "--commit",
            "0123456789abcdef",
        ],
    )

    assert result.exit_code == 0
    assert "Import complete" in result.stdout
    assert "created findings: 1" in result.stdout
    assert "observations created: 1" in result.stdout


def test_import_semgrep_command_rejects_invalid_json(tmp_path: Path) -> None:
    invalid_report = tmp_path / "invalid-report.json"
    invalid_report.write_text("not valid json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "import-semgrep",
            str(invalid_report),
            "--repository",
            "demo/vulnerable-service",
            "--commit",
            "0123456789abcdef",
        ],
    )

    assert result.exit_code == 2
    assert "is not valid JSON" in result.stderr