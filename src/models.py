from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base, utcnow_naive


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str | None] = mapped_column(String(320), unique=True, index=True, nullable=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, nullable=False)
    profile: Mapped["UserProfile"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
    )
    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    auth_challenges: Mapped[list["AuthChallenge"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    identities: Mapped[list["OAuthIdentity"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    master_cv: Mapped["MasterCV | None"] = relationship(
        back_populates="user", cascade="all, delete-orphan", uselist=False
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


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    user: Mapped[User] = relationship(back_populates="auth_challenges")


class OAuthIdentity(Base):
    __tablename__ = "oauth_identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, nullable=False)
    user: Mapped[User] = relationship(back_populates="identities")
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_oauth_issuer_subject"),)


class MasterCV(Base):
    __tablename__ = "master_cvs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False
    )
    content: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow_naive, nullable=False)
    user: Mapped[User] = relationship(back_populates="master_cv")
