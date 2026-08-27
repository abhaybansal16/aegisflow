import json
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from aegisflow.adapters.trivy import parse_trivy_report
from aegisflow.db.models import Finding, Observation, Repository, ScanRun
from aegisflow.db.session import create_db_engine
from aegisflow.services.imports import import_normalized_findings

FIXTURE_PATH = Path("tests/fixtures/trivy_report.json")


def load_fixture() -> dict:
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


def trivy_raw_vulnerabilities(report: dict) -> list[dict]:
    """Flatten fixture vulnerabilities in the same order as the adapter output."""

    raw_payloads = []
    for result in report["Results"]:
        raw_payloads.extend(result.get("Vulnerabilities", []))
    return raw_payloads


def test_normalized_trivy_findings_use_the_shared_import_workflow() -> None:
    clear_aegisflow_tables()
    report = load_fixture()
    findings = parse_trivy_report(
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
            raw_payloads=trivy_raw_vulnerabilities(report),
            source_report=report,
        )

        assert summary.created_findings == 2
        assert summary.reused_findings == 0
        assert summary.observations_created == 2

        with Session(engine) as session:
            assert table_count(session, Repository) == 1
            assert table_count(session, ScanRun) == 1
            assert table_count(session, Finding) == 2
            assert table_count(session, Observation) == 2

            observations = list(
                session.scalars(
                    select(Observation).where(Observation.tool == "trivy")
                )
            )
            assert len(observations) == 2
            assert observations[0].location_path is None
            assert observations[0].raw_payload["PkgName"] == "requests"
    finally:
        engine.dispose()


def test_shared_import_rejects_mismatched_raw_evidence() -> None:
    report = load_fixture()
    findings = parse_trivy_report(
        report=report,
        repository="demo/vulnerable-service",
        commit_sha="0123456789abcdef",
    )
    engine = create_db_engine()
    try:
        with pytest.raises(ValueError, match="exactly one raw payload"):
            import_normalized_findings(
                engine=engine,
                repository_full_name="demo/vulnerable-service",
                commit_sha="0123456789abcdef",
                findings=findings,
                raw_payloads=trivy_raw_vulnerabilities(report)[:1],
                source_report=report,
            )
    finally:
        engine.dispose()