from aegisflow.db.session import create_db_engine, get_database_identity


def test_local_postgres_connection() -> None:
    engine = create_db_engine()
    database_name, database_user = get_database_identity(engine)
    engine.dispose()

    assert database_name == "aegisflow"
    assert database_user == "aegisflow"