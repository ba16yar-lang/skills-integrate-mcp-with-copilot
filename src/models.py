from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base, utcnow_naive


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, nullable=False)
    profile: Mapped["UserProfile"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class UserProfile(Base):
    __tablename__ = "user_profiles"

    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    full_name: Mapped[str] = mapped_column(String(120), default="", nullable=False)
    locale: Mapped[str] = mapped_column(String(16), default="en-GB", nullable=False)
    user: Mapped[User] = relationship(back_populates="profile")


class UserSession(Base):
    __tablename__ = "user_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    csrf_token: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    user: Mapped[User] = relationship(back_populates="sessions")
