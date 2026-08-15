"""Read local application configuration without committing secrets."""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    """Settings required by the application during the database milestone."""

    database_url: str


def get_settings() -> Settings:
    """Return validated settings from the local environment."""

    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required. Add it to your local .env file.")
    return Settings(database_url=database_url)