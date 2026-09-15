"""Engine and session setup.

The engine is a connection pool created once per process. A Session is a
short-lived unit of work borrowed from that pool -- open one, do the writes,
commit, close.
"""
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

engine = create_engine(
    get_settings().database_url,
    pool_pre_ping=True,  # discard connections the DB has silently dropped
    future=True,
)

SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Commit on success, roll back on any exception, always close."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
