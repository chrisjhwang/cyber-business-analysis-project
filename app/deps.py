"""FastAPI dependencies.

`DbSession` in a route signature tells FastAPI: before calling this function,
open a session from the pool; after the response is sent, close it. Each
request gets its own session, so concurrent requests never share one.
"""
from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.db import SessionLocal


def get_db() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


DbSession = Annotated[Session, Depends(get_db)]
