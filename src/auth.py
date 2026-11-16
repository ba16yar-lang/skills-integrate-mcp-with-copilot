import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager
from datetime import datetime, timedelta
from math import ceil
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.database import get_db, utcnow_naive
from src.models import User, UserProfile, UserSession


SESSION_COOKIE = "core456_session"
SESSION_TTL = timedelta(days=14)
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
AUTH_RATE_WINDOW_SECONDS = 60
AUTH_RATE_LIMITS = {"register": 5, "login": 10}
MAX_RATE_LIMIT_CLIENTS = 4096
_auth_attempts: OrderedDict[tuple[str, str], tuple[deque[float], float]] = OrderedDict()
_auth_attempts_lock = threading.Lock()
_password_hash_slots = threading.BoundedSemaphore(value=4)
router = APIRouter(prefix="/auth", tags=["authentication"])
profile_router = APIRouter(prefix="/profile", tags=["profile"])


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=128)
    full_name: str = Field(default="", max_length=120)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().casefold()
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("A valid email address is required")
        return value


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().casefold()
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("A valid email address is required")
        return value


class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    locale: str
    csrf_token: str | None = None


class ProfileUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    full_name: str = Field(min_length=1, max_length=120)
    locale: str = Field(min_length=2, max_length=16)

    @field_validator("full_name")
    @classmethod
    def require_nonblank_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("A non-empty name is required")
        return value


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=64)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, digest_hex = encoded.split("$")
        if algorithm != "scrypt":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.scrypt(
            password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1, dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


DUMMY_PASSWORD_HASH = hash_password("constant-time-placeholder-password")


def _enforce_auth_rate_limit(request: Request, action: str) -> None:
    now = time.monotonic()
    cutoff = now - AUTH_RATE_WINDOW_SECONDS
    client_host = request.client.host if request.client else "unknown"
    key = (action, client_host)
    with _auth_attempts_lock:
        while _auth_attempts:
            oldest_key, (_, last_seen) = next(iter(_auth_attempts.items()))
            if last_seen > cutoff:
                break
            _auth_attempts.pop(oldest_key)

        attempts, _ = _auth_attempts.get(key, (deque(), now))
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if len(attempts) >= AUTH_RATE_LIMITS[action]:
            retry_after = max(1, ceil(attempts[0] + AUTH_RATE_WINDOW_SECONDS - now))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many authentication attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )
        attempts.append(now)
        _auth_attempts[key] = (attempts, now)
        _auth_attempts.move_to_end(key)
        while len(_auth_attempts) > MAX_RATE_LIMIT_CLIENTS:
            _auth_attempts.popitem(last=False)


@contextmanager
def _password_hash_slot():
    if not _password_hash_slots.acquire(timeout=2):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Authentication is busy. Try again shortly.",
            headers={"Retry-After": "2"},
        )
    try:
        yield
    finally:
        _password_hash_slots.release()


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=int(SESSION_TTL.total_seconds()),
        httponly=True,
        secure=os.getenv("COOKIE_SECURE", "").casefold() in {"1", "true", "yes"}
        or os.getenv("ENVIRONMENT", "").casefold() == "production",
        samesite="lax",
        path="/",
    )


def _create_session(db: Session, user: User, response: Response) -> str:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    db.add(
        UserSession(
            token_hash=_token_digest(token),
            user_id=user.id,
            csrf_token=csrf_token,
            expires_at=utcnow_naive() + SESSION_TTL,
        )
    )
    db.commit()
    _set_session_cookie(response, token)
    return csrf_token


def _user_response(user: User, csrf_token: str | None = None) -> UserResponse:
    profile = user.profile
    return UserResponse(
        id=user.id,
        email=user.email,
        full_name=profile.full_name if profile else "",
        locale=profile.locale if profile else "en-GB",
        csrf_token=csrf_token,
    )


def get_current_session(
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
    db: Session = Depends(get_db),
) -> UserSession:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == _token_digest(session_token),
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > utcnow_naive(),
        )
    )
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return session


def require_csrf(
    session: Annotated[UserSession, Depends(get_current_session)],
    csrf_header: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> UserSession:
    if not csrf_header or not hmac.compare_digest(session.csrf_token, csrf_header):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token")
    return session


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    _enforce_auth_rate_limit(request, "register")
    with _password_hash_slot():
        password_hash = hash_password(payload.password)
    user = User(email=payload.email, password_hash=password_hash)
    user.profile = UserProfile(full_name=payload.full_name.strip(), locale="en-GB")
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists") from exc
    csrf_token = _create_session(db, user, response)
    return _user_response(user, csrf_token)


@router.post("/login", response_model=UserResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    _enforce_auth_rate_limit(request, "login")
    user = db.scalar(select(User).where(User.email == payload.email))
    with _password_hash_slot():
        password_matches = verify_password(
            payload.password,
            user.password_hash if user else DUMMY_PASSWORD_HASH,
        )
    if not user or not password_matches:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    csrf_token = _create_session(db, user, response)
    return _user_response(user, csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    session: Annotated[UserSession, Depends(require_csrf)],
    db: Session = Depends(get_db),
) -> Response:
    session.revoked_at = utcnow_naive()
    db.commit()
    response.delete_cookie(key=SESSION_COOKIE, path="/", httponly=True, samesite="lax")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me", response_model=UserResponse)
def current_user(
    session: Annotated[UserSession, Depends(get_current_session)],
    db: Session = Depends(get_db),
) -> UserResponse:
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return _user_response(user)


@router.get("/csrf")
def csrf_token(session: Annotated[UserSession, Depends(get_current_session)]) -> dict[str, str]:
    return {"csrf_token": session.csrf_token}


@profile_router.get("/me", response_model=UserResponse)
def get_profile(
    session: Annotated[UserSession, Depends(get_current_session)],
    db: Session = Depends(get_db),
) -> UserResponse:
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return _user_response(user)


@profile_router.put("/me", response_model=UserResponse)
def update_profile(
    payload: ProfileUpdate,
    session: Annotated[UserSession, Depends(require_csrf)],
    db: Session = Depends(get_db),
) -> UserResponse:
    user = db.get(User, session.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user.profile.full_name = payload.full_name.strip()
    user.profile.locale = payload.locale
    db.commit()
    return _user_response(user)
