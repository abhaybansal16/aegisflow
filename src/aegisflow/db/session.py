"""Create and verify PostgreSQL connections for AegisFlow."""

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from aegisflow.config import get_settings


def create_db_engine() -> Engine:
    """Create a reusable SQLAlchemy engine from the local DATABASE_URL."""

    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True)


def get_database_identity(engine: Engine) -> tuple[str, str]:
    """Return the connected database and PostgreSQL role as a connection check."""

    with engine.connect() as connection:
        database_name = connection.execute(text("SELECT current_database()")).scalar_one()
        database_user = connection.execute(text("SELECT current_user")).scalar_one()
    return database_name, database_user