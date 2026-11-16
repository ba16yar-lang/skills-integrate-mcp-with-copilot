import os
from collections.abc import Generator
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./core456.db")
_engine_options = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **_engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_db() -> Generator[Session, None, None]:
    with SessionLocal() as session:
        yield session
