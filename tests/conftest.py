"""Shared test setup.

Tests that need Postgres use the `db` fixture. They run against a SEPARATE
database (<your db name>_test), created and migrated automatically, so running
the suite never touches the data you ingested. Pure tests (scoring, parsing,
HTTP retry logic) need no database and run anywhere.

If Postgres is not running, DB tests are skipped with a message, unless
REQUIRE_DB=1 is set (CI sets it, so a broken database fails the build rather
than silently skipping half the suite).
"""
import json
import os
from pathlib import Path
from typing import Any

import pytest
from dotenv import dotenv_values
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _resolve_test_url() -> str:
    if url := os.environ.get("TEST_DATABASE_URL"):
        return url
    base = os.environ.get("DATABASE_URL") or dotenv_values(ROOT / ".env").get("DATABASE_URL")
    if not base:
        return "postgresql+psycopg2://postgres:postgres@localhost:5432/cyber_risk_test"
    url = make_url(base)
    return url.set(database=f"{url.database}_test").render_as_string(hide_password=False)


TEST_DATABASE_URL = _resolve_test_url()
# Must run before anything imports app.db, which builds its engine from
# DATABASE_URL at import time. conftest.py is imported before any test module.
os.environ["DATABASE_URL"] = TEST_DATABASE_URL


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text())


def _ensure_database(url_str: str) -> None:
    url = make_url(url_str)
    # CREATE DATABASE cannot run inside a transaction, hence AUTOCOMMIT, and it
    # must be issued from a different database than the one being created.
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            exists = conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": url.database}
            )
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{url.database}"'))
    finally:
        admin.dispose()


@pytest.fixture(scope="session")
def db_engine():
    try:
        _ensure_database(TEST_DATABASE_URL)
    except OperationalError as exc:
        if os.environ.get("REQUIRE_DB"):
            raise
        pytest.skip(f"Postgres not reachable, start it with `docker compose up -d db` ({exc.orig})")

    # Build the schema with the real migrations rather than create_all(), so
    # the suite also proves the migrations produce what the models expect.
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", TEST_DATABASE_URL.replace("%", "%%"))
    command.upgrade(cfg, "head")

    from app.db import engine

    yield engine


@pytest.fixture
def db(db_engine):
    """A session on an empty database. Tables are truncated BEFORE each test,
    so a failed test leaves its data behind for inspection."""
    with db_engine.begin() as conn:
        conn.execute(text("TRUNCATE risk_scores, assets, vulnerabilities RESTART IDENTITY CASCADE"))
    from app.db import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def client(db):
    """FastAPI in-process: real routing and validation, no server or port."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client
