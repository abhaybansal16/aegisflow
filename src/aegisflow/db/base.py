"""Shared SQLAlchemy declarative base for all AegisFlow database models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """The parent class that collects every table's metadata for Alembic."""

