from sqlalchemy import text
from typer.testing import CliRunner

from aegisflow.cli import app
from aegisflow.db.session import create_db_engine

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


def test_import_gitleaks_command_imports_fixture() -> None:
    clear_aegisflow_tables()

    result = runner.invoke(
        app,
        [
            "import-gitleaks",
            "tests/fixtures/gitleaks_report.json",
            "--repository",
            "demo/vulnerable-service",
            "--commit",
            "0123456789abcdef",
        ],
    )

    assert result.exit_code == 0
    assert "Import complete" in result.stdout
    assert "created findings: 1" in result.stdout


def test_import_gitleaks_command_rejects_a_report_that_is_not_a_json_array(
    tmp_path,
) -> None:
    not_an_array = tmp_path / "not-an-array.json"
    not_an_array.write_text('{"leaks": []}', encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "import-gitleaks",
            str(not_an_array),
            "--repository",
            "demo/repo",
            "--commit",
            "abc",
        ],
    )

    assert result.exit_code == 1
    assert "must contain a JSON array" in result.stderr


def test_import_gitleaks_command_rejects_invalid_json(tmp_path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("not json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "import-gitleaks",
            str(invalid_json),
            "--repository",
            "demo/repo",
            "--commit",
            "abc",
        ],
    )

    assert result.exit_code == 1
    assert "is not valid JSON" in result.stderr
