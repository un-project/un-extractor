"""Database connection and session management.

Usage
-----
    from src.db.database import get_engine, get_session

    engine = get_engine()           # reads DATABASE_URL from environment
    with get_session(engine) as session:
        session.add(some_orm_object)
        session.commit()

Schema creation
---------------
    from src.db.database import create_schema
    create_schema(engine)
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, Engine
from sqlalchemy.orm import Session, sessionmaker

from src.db.models import Base


def get_engine(url: str | None = None) -> Engine:
    """Return a SQLAlchemy engine.

    Parameters
    ----------
    url:
        Database URL (e.g. ``postgresql://user:pass@host/db``).
        Falls back to the ``DATABASE_URL`` environment variable.

    Raises
    ------
    ValueError
        If no URL is provided and ``DATABASE_URL`` is not set.
    """
    if url is None:
        url = os.environ.get("DATABASE_URL")
    if not url:
        raise ValueError(
            "No database URL provided.  Set DATABASE_URL or pass url= explicitly."
        )
    return create_engine(url, pool_pre_ping=True)


def create_schema(engine: Engine) -> None:
    """Create all tables defined in the ORM models (no-op if they exist)."""
    Base.metadata.create_all(engine)


def drop_schema(engine: Engine) -> None:
    """Drop all tables.  USE WITH CAUTION — data loss is permanent."""
    Base.metadata.drop_all(engine)


@contextmanager
def get_session(engine: Engine) -> Generator[Session, None, None]:
    """Context manager that yields a ``Session`` and commits on exit.

    Rolls back on exception and always closes the session.
    """
    factory = sessionmaker(bind=engine)
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
