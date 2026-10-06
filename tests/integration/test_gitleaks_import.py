import json
from pathlib import Path

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from aegisflow.adapters.gitleaks import parse_gitleaks_report
from aegisflow.db.models import Finding, Observation, Repository, ScanRun
from aegisflow.db.session import create_db_engine
from aegisflow.services.imports import import_normalized_findings

FIXTURE_PATH = Path("tests/fixtures/gitleaks_report.json")


def load_fixture() -> list:
    with FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def clear_aegisflow_tables() -> None:
    """Keep every integration test independent in the local development database."""

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


def test_normalized_gitleaks_findings_use_the_shared_import_workflow() -> None:
    clear_aegisflow_tables()
    report = load_fixture()
    findings = parse_gitleaks_report(
        report=report,
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )
    engine = create_db_engine()
    try:
        summary = import_normalized_findings(
            engine=engine,
            repository_full_name="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
            findings=findings,
            raw_payloads=report,
            source_report={"leaks": report},
        )

        assert summary.created_findings == 1
        assert summary.reused_findings == 0
        assert summary.observations_created == 1

        with Session(engine) as session:
            assert table_count(session, Repository) == 1
            assert table_count(session, ScanRun) == 1
            assert table_count(session, Finding) == 1
            assert table_count(session, Observation) == 1

            observation = session.scalar(
                select(Observation).where(Observation.tool == "gitleaks")
            )
            assert observation is not None
            assert observation.location_path == "src/config.py"
            assert observation.raw_payload["RuleID"] == "generic-api-key"
    finally:
        engine.dispose()


def test_reimport_reuses_the_gitleaks_finding_and_adds_new_evidence() -> None:
    clear_aegisflow_tables()
    report = load_fixture()
    findings = parse_gitleaks_report(
        report=report,
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )
    engine = create_db_engine()
    try:
        first_import = import_normalized_findings(
            engine=engine,
            repository_full_name="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
            findings=findings,
            raw_payloads=report,
            source_report={"leaks": report},
        )
        second_import = import_normalized_findings(
            engine=engine,
            repository_full_name="demo/vulnerable-service",
            commit_sha="0123456789abcdef",
            findings=findings,
            raw_payloads=report,
            source_report={"leaks": report},
        )

        assert first_import.created_findings == 1
        assert second_import.created_findings == 0
        assert second_import.reused_findings == 1

        with Session(engine) as session:
            assert table_count(session, ScanRun) == 2
            assert table_count(session, Finding) == 1
            assert table_count(session, Observation) == 2
    finally:
        engine.dispose()
