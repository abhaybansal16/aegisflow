from sqlalchemy import inspect

from aegisflow.db.session import create_db_engine


def test_initial_aegisflow_tables_exist() -> None:
    engine = create_db_engine()
    inspector = inspect(engine)

    try:
        table_names = set(inspector.get_table_names())
    finally:
        engine.dispose()

    expected_tables = {"repositories", "scan_runs", "findings", "observations"}
    assert expected_tables.issubset(table_names)
