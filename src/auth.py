import hashlib
import hmac
import os
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Annotated
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.database import get_db, utcnow_naive
from src.models import AuthChallenge, OAuthIdentity, User, UserProfile, UserSession
from src.security_services import RATE_LIMITS, _attempts, _attempts_lock, enforce_rate_limit, send_account_email


SESSION_COOKIE = "core456_session"
SESSION_TTL = timedelta(days=14)
EMAIL_PATTERN = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$")
CHALLENGE_TTL = timedelta(hours=1)
AUTH_RATE_LIMITS = RATE_LIMITS
AUTH_RATE_WINDOW_SECONDS = 60
_auth_attempts = _attempts
_auth_attempts_lock = _attempts_lock
_password_hash_slots = threading.BoundedSemaphore(value=4)
_oauth_clients_lock = threading.Lock()
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
    email: str | None
    email_verified: bool
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


class EmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().casefold()
        if not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("A valid email address is required")
        return value


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=32, max_length=128)


class PasswordResetRequest(TokenRequest):
    new_password: str = Field(min_length=12, max_length=128)


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
_oauth = OAuth()


def _oidc_settings(provider: str) -> dict[str, str] | None:
    if provider == "google":
        client_id = os.getenv("GOOGLE_CLIENT_ID")
        client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
    elif provider == "microsoft":
        client_id = os.getenv("MICROSOFT_CLIENT_ID")
        client_secret = os.getenv("MICROSOFT_CLIENT_SECRET")
        tenant = os.getenv("MICROSOFT_TENANT_ID", "")
        if not tenant or not re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?", tenant
        ) or ".." in tenant:
            return None
        discovery_url = f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
    elif provider == "oidc":
        client_id = os.getenv("OIDC_CLIENT_ID")
        client_secret = os.getenv("OIDC_CLIENT_SECRET")
        discovery_url = os.getenv("OIDC_DISCOVERY_URL", "")
        if not discovery_url.startswith("https://"):
            return None
    else:
        return None

    if not client_id or not client_secret or not discovery_url.startswith("https://"):
        return None
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "discovery_url": discovery_url,
    }


def _oidc_client(provider: str):
    settings = _oidc_settings(provider)
    if not settings:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity provider is not configured")
    with _oauth_clients_lock:
        client = _oauth.create_client(provider)
        if client is None:
            client = _oauth.register(
                name=provider,
                client_id=settings["client_id"],
                client_secret=settings["client_secret"],
                server_metadata_url=settings["discovery_url"],
                client_kwargs={"scope": "openid email profile", "code_challenge_method": "S256"},
            )
        return client


def _oauth_redirect_uri(provider: str) -> str:
    base_url = os.getenv("OAUTH_REDIRECT_BASE_URL", "").rstrip("/")
    parsed = urlsplit(base_url)
    safe_https = parsed.scheme == "https" and bool(parsed.hostname)
    safe_local_http = (
        parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
    )
    if (
        not base_url
        or not (safe_https or safe_local_http)
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth redirect URL is not configured",
        )
    return f"{base_url}/auth/oauth/{provider}/callback"


@router.get("/providers")
def oauth_providers() -> dict[str, list[str]]:
    return {"providers": [name for name in ("google", "microsoft", "oidc") if _oidc_settings(name)]}


@router.get("/oauth/{provider}")
async def oauth_start(provider: str, request: Request):
    _enforce_auth_rate_limit(request, "oauth_start")
    if not os.getenv("APP_SECRET_KEY") or len(os.getenv("APP_SECRET_KEY", "")) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth state signing is not configured",
        )
    client = _oidc_client(provider)
    return await client.authorize_redirect(request, _oauth_redirect_uri(provider))


@router.get("/oauth/{provider}/callback", name="oauth_callback")
async def oauth_callback(provider: str, request: Request, db: Session = Depends(get_db)):
    _enforce_auth_rate_limit(request, "oauth_callback")
    if not os.getenv("APP_SECRET_KEY") or len(os.getenv("APP_SECRET_KEY", "")) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OAuth state signing is not configured",
        )
    client = _oidc_client(provider)
    try:
        token = await client.authorize_access_token(request)
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identity sign-in failed") from exc

    claims = token.get("userinfo")
    if not claims:
        try:
            claims = await client.userinfo(token=token)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identity sign-in failed") from exc
    issuer = claims.get("iss")
    subject = claims.get("sub")
    if not isinstance(issuer, str) or not isinstance(subject, str) or not subject:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identity sign-in failed")

    identity = db.scalar(
        select(OAuthIdentity).where(OAuthIdentity.issuer == issuer, OAuthIdentity.subject == subject)
    )
    if identity:
        user = db.get(User, identity.user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Identity sign-in failed")
    else:
        email = claims.get("email")
        verified_claim = claims.get("email_verified")
        email_verified = verified_claim is True or (
            isinstance(verified_claim, str) and verified_claim.casefold() == "true"
        )
        if not email_verified or not isinstance(email, str) or not EMAIL_PATTERN.fullmatch(email):
            email = None
            email_verified = False
        else:
            email = email.strip().casefold()
            if db.scalar(select(User.id).where(User.email == email)):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="An account with this email already exists. Sign in to link an identity.",
                )
        user = User(
            email=email,
            password_hash=None,
            email_verified=email_verified,
            email_verified_at=utcnow_naive() if email_verified else None,
        )
        profile_name = claims.get("name")
        user.profile = UserProfile(
            full_name=profile_name[:120] if isinstance(profile_name, str) else "",
            locale="en-GB",
        )
        user.identities.append(OAuthIdentity(issuer=issuer, subject=subject))
        db.add(user)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Identity sign-in failed") from exc
    redirect = RedirectResponse(url="/static/account.html?oauth=success", status_code=303)
    _create_session(db, user, redirect)
    return redirect


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


def _enforce_auth_rate_limit(request: Request, action: str, identifier: str | None = None) -> None:
    client_host = request.client.host if request.client else "unknown"
    enforce_rate_limit(action, client_host, identifier)


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _issue_auth_challenge(db: Session, user: User, purpose: str) -> None:
    if not user.email:
        return
    now = utcnow_naive()
    db.execute(
        update(AuthChallenge)
        .where(
            AuthChallenge.user_id == user.id,
            AuthChallenge.purpose == purpose,
            AuthChallenge.consumed_at.is_(None),
        )
        .values(consumed_at=now)
    )
    token = secrets.token_urlsafe(32)
    db.add(
        AuthChallenge(
            token_hash=_token_digest(token),
            user_id=user.id,
            purpose=purpose,
            expires_at=now + CHALLENGE_TTL,
        )
    )
    db.commit()
    base_url = os.getenv("PUBLIC_APP_URL", "http://localhost:8000").rstrip("/")
    if purpose == "verify_email":
        subject = "Verify your ResuMint email address"
        link = f"{base_url}/static/account.html#verify={token}"
    else:
        subject = "Reset your ResuMint password"
        link = f"{base_url}/static/account.html#reset={token}"
    send_account_email(
        user.email,
        subject,
        f"Use this link within one hour to continue: {link}\n"
        "If you did not request this, you can ignore this message.",
    )


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
        email_verified=user.email_verified,
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
    _enforce_auth_rate_limit(request, "register", payload.email)
    with _password_hash_slot():
        password_hash = hash_password(payload.password)
    user = User(email=payload.email, password_hash=password_hash, email_verified=False)
    user.profile = UserProfile(full_name=payload.full_name.strip(), locale="en-GB")
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="An account with this email already exists") from exc
    try:
        _issue_auth_challenge(db, user, "verify_email")
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Verification email could not be sent. Please request another email.",
        ) from exc
    return _user_response(user)


@router.post("/verify-email", response_model=UserResponse)
def verify_email(
    payload: TokenRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    _enforce_auth_rate_limit(request, "verify_email", _token_digest(payload.token))
    challenge = db.scalar(
        select(AuthChallenge).where(
            AuthChallenge.token_hash == _token_digest(payload.token),
            AuthChallenge.purpose == "verify_email",
            AuthChallenge.consumed_at.is_(None),
            AuthChallenge.expires_at > utcnow_naive(),
        )
    )
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification link")
    now = utcnow_naive()
    consumed = db.execute(
        update(AuthChallenge)
        .where(
            AuthChallenge.token_hash == challenge.token_hash,
            AuthChallenge.consumed_at.is_(None),
            AuthChallenge.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if consumed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification link")
    user = db.get(User, challenge.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification link")
    user.email_verified = True
    user.email_verified_at = now
    db.commit()
    csrf_token = _create_session(db, user, response)
    return _user_response(user, csrf_token)


@router.post("/request-verification", status_code=status.HTTP_202_ACCEPTED)
def request_verification(
    payload: EmailRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    _enforce_auth_rate_limit(request, "verify_request", payload.email)
    user = db.scalar(select(User).where(User.email == payload.email))
    if user and not user.email_verified:
        try:
            _issue_auth_challenge(db, user, "verify_email")
        except Exception:
            pass
    return {"message": "If this account needs verification, an email will be sent."}


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    payload: EmailRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    _enforce_auth_rate_limit(request, "password_reset_request", payload.email)
    user = db.scalar(select(User).where(User.email == payload.email))
    if user:
        try:
            _issue_auth_challenge(db, user, "reset_password")
        except Exception:
            pass
    return {"message": "If an account exists for this address, password reset instructions will be sent."}


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(
    payload: PasswordResetRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> Response:
    _enforce_auth_rate_limit(request, "password_reset", _token_digest(payload.token))
    challenge = db.scalar(
        select(AuthChallenge).where(
            AuthChallenge.token_hash == _token_digest(payload.token),
            AuthChallenge.purpose == "reset_password",
            AuthChallenge.consumed_at.is_(None),
            AuthChallenge.expires_at > utcnow_naive(),
        )
    )
    if not challenge:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset link")
    now = utcnow_naive()
    consumed = db.execute(
        update(AuthChallenge)
        .where(
            AuthChallenge.token_hash == challenge.token_hash,
            AuthChallenge.consumed_at.is_(None),
            AuthChallenge.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if consumed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset link")
    user = db.get(User, challenge.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset link")
    with _password_hash_slot():
        user.password_hash = hash_password(payload.new_password)
    user.credential_version += 1
    user.email_verified = True
    user.email_verified_at = user.email_verified_at or utcnow_naive()
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow_naive())
    )
    db.commit()
    response.delete_cookie(key=SESSION_COOKIE, path="/", httponly=True, samesite="lax")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.post("/login", response_model=UserResponse)
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    db: Session = Depends(get_db),
) -> UserResponse:
    _enforce_auth_rate_limit(request, "login", payload.email)
    user = db.scalar(select(User).where(User.email == payload.email))
    password_hash = user.password_hash if user else DUMMY_PASSWORD_HASH
    credential_version = user.credential_version if user else 0
    with _password_hash_slot():
        password_matches = verify_password(payload.password, password_hash or DUMMY_PASSWORD_HASH)
    if not user or not user.password_hash or not password_matches or not user.email_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")
    credential_is_current = db.execute(
        update(User)
        .where(
            User.id == user.id,
            User.password_hash == password_hash,
            User.credential_version == credential_version,
            User.email_verified.is_(True),
        )
        .values(credential_version=User.credential_version)
    )
    if credential_is_current.rowcount != 1:
        db.rollback()
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
