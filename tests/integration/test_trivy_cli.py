from typer.testing import CliRunner

from aegisflow.cli import app

runner = CliRunner()


def test_import_trivy_command_imports_fixture() -> None:
    result = runner.invoke(
        app,
        [
            "import-trivy",
            "tests/fixtures/trivy_report.json",
            "--repository",
            "demo/vulnerable-service",
            "--commit",
            "0123456789abcdef",
        ],
    )

    assert result.exit_code == 0
    assert "Import complete" in result.stdout
    assert (
        "created findings: 2" in result.stdout or "reused findings: 2" in result.stdout
    )


def test_import_trivy_command_rejects_invalid_json(tmp_path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("not json")

    result = runner.invoke(
        app,
        [
            "import-trivy",
            str(invalid_json),
            "--repository",
            "demo/repo",
            "--commit",
            "abc",
        ],
    )

    assert result.exit_code == 1
    assert "is not valid JSON" in result.stderr
