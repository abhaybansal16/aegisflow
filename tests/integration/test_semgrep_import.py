import json
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from aegisflow.db.models import Finding, Observation, Repository, ScanRun
from aegisflow.db.session import create_db_engine
from aegisflow.services.imports import import_semgrep_report

FIXTURE_PATH = Path("tests/fixtures/semgrep_report.json")


def load_fixture() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def clear_aegisflow_tables() -> None:
    """Keep every integration test independent while this is a local-only database."""

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


def table_count(session: Session, model: object) -> int:
    """Return the number of rows for one SQLAlchemy model."""

    return session.scalar(select(func.count()).select_from(model)) or 0


def test_import_creates_the_first_scan_and_finding() -> None:
    clear_aegisflow_tables()
    engine = create_db_engine()
    try:
        summary = import_semgrep_report(
            engine=engine,
            report=load_fixture(),
            repository_full_name="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
        )

        assert summary.created_findings == 1
        assert summary.reused_findings == 0
        assert summary.observations_created == 1

        with Session(engine) as session:
            assert table_count(session, Repository) == 1
            assert table_count(session, ScanRun) == 1
            assert table_count(session, Finding) == 1
            assert table_count(session, Observation) == 1

            observation = session.scalar(select(Observation))
            assert observation is not None
            assert observation.tool == "semgrep"
            assert observation.raw_payload["check_id"] == (
                "python.flask.security.injection.sqlalchemy.text"
            )
    finally:
        engine.dispose()


def test_reimport_reuses_the_finding_and_adds_new_evidence() -> None:
    clear_aegisflow_tables()
    engine = create_db_engine()
    try:
        first_import = import_semgrep_report(
            engine=engine,
            report=load_fixture(),
            repository_full_name="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
        )
        second_import = import_semgrep_report(
            engine=engine,
            report=load_fixture(),
            repository_full_name="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
        )

        assert first_import.created_findings == 1
        assert second_import.created_findings == 0
        assert second_import.reused_findings == 1

        with Session(engine) as session:
            assert table_count(session, Repository) == 1
            assert table_count(session, ScanRun) == 2
            assert table_count(session, Finding) == 1
            assert table_count(session, Observation) == 2
    finally:
        engine.dispose()