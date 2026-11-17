from collections.abc import Iterator
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src import auth
from src.authorization import authorize_resource_access
from src import security_services
from src.app import app
from src.database import Base, get_db
from src.models import User


@pytest.fixture
def email_outbox(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, str]]:
    outbox: list[tuple[str, str, str]] = []
    monkeypatch.setattr(auth, "send_account_email", lambda *message: outbox.append(message))
    return outbox


@pytest.fixture
def client(email_outbox: list[tuple[str, str, str]]) -> Iterator[TestClient]:
    with auth._auth_attempts_lock:
        auth._auth_attempts.clear()
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db() -> Iterator[Session]:
        with test_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        test_client.app.state.test_session_factory = test_session
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()
    with auth._auth_attempts_lock:
        auth._auth_attempts.clear()


def register(client: TestClient, email: str, email_outbox: list[tuple[str, str, str]]) -> dict:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "a-secure-password-123", "full_name": "Taylor Example"},
    )
    assert response.status_code == 201
    assert response.json()["email_verified"] is False
    link = next(word for word in email_outbox[-1][2].split() if word.startswith("http"))
    token = parse_qs(urlparse(link).fragment)["verify"][0]
    verified = client.post("/auth/verify-email", json={"token": token})
    assert verified.status_code == 200
    return verified.json()


def test_registration_normalizes_email_and_authenticates(
    client: TestClient, email_outbox: list[tuple[str, str, str]]
) -> None:
    result = register(client, " Taylor@Example.com ", email_outbox)

    assert result["email"] == "taylor@example.com"
    assert result["email_verified"] is True
    assert client.cookies.get("core456_session")
    assert client.get("/auth/me").json()["id"] == result["id"]
    assert client.get("/profile/me").json()["full_name"] == "Taylor Example"
    verification_link = next(word for word in email_outbox[0][2].split() if word.startswith("http"))
    verification_token = parse_qs(urlparse(verification_link).fragment)["verify"][0]
    assert client.post("/auth/verify-email", json={"token": verification_token}).status_code == 400


def test_duplicate_registration_and_weak_password_are_rejected(
    client: TestClient, email_outbox: list[tuple[str, str, str]]
) -> None:
    register(client, "taylor@example.com", email_outbox)
    duplicate = client.post(
        "/auth/register",
        json={"email": "TAYLOR@example.com", "password": "a-secure-password-123"},
    )
    weak_password = client.post(
        "/auth/register",
        json={"email": "new@example.com", "password": "short"},
    )

    assert duplicate.status_code == 409
    assert weak_password.status_code == 422


def test_login_logout_and_revocation(client: TestClient, email_outbox: list[tuple[str, str, str]]) -> None:
    register(client, "taylor@example.com", email_outbox)
    client.post("/auth/logout", headers={"X-CSRF-Token": "invalid"})
    assert client.get("/auth/me").status_code == 200

    csrf_token = client.get("/auth/csrf").json()["csrf_token"]
    logout = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})

    assert logout.status_code == 204
    assert client.get("/auth/me").status_code == 401
    login = client.post(
        "/auth/login",
        json={"email": "TAYLOR@example.com", "password": "a-secure-password-123"},
    )
    assert login.status_code == 200
    assert client.get("/auth/me").status_code == 200


def test_profile_updates_require_csrf_and_are_user_scoped(
    client: TestClient, email_outbox: list[tuple[str, str, str]]
) -> None:
    first = register(client, "first@example.com", email_outbox)
    csrf = first["csrf_token"]
    update = client.put(
        "/profile/me",
        headers={"X-CSRF-Token": csrf},
        json={"full_name": "Updated Name", "locale": "en-GB"},
    )
    assert update.status_code == 200
    assert client.put(
        "/profile/me",
        json={"full_name": "No CSRF", "locale": "en-GB"},
    ).status_code == 403
    assert client.put(
        "/profile/me",
        headers={"X-CSRF-Token": csrf},
        json={"full_name": "   ", "locale": "en-GB"},
    ).status_code == 422

    client.post("/auth/logout", headers={"X-CSRF-Token": csrf})
    register(client, "second@example.com", email_outbox)
    own_profile = client.get("/profile/me").json()
    assert own_profile["email"] == "second@example.com"
    assert own_profile["full_name"] == "Taylor Example"


def test_invalid_login_does_not_authenticate(client: TestClient, email_outbox: list[tuple[str, str, str]]) -> None:
    register(client, "taylor@example.com", email_outbox)
    client.post("/auth/logout", headers={"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]})
    response = client.post(
        "/auth/login",
        json={"email": "taylor@example.com", "password": "not-the-right-password"},
    )
    assert response.status_code == 401
    assert client.get("/auth/me").status_code == 401


def test_registration_and_login_attempts_are_rate_limited(client: TestClient) -> None:
    for index in range(auth.AUTH_RATE_LIMITS["register"]):
        response = client.post(
            "/auth/register",
            json={
                "email": f"account-{index}@example.com",
                "password": "a-secure-password-123",
            },
        )
        assert response.status_code == 201

    limited_registration = client.post(
        "/auth/register",
        json={"email": "last@example.com", "password": "a-secure-password-123"},
    )
    assert limited_registration.status_code == 429
    assert 1 <= int(limited_registration.headers["retry-after"]) <= auth.AUTH_RATE_WINDOW_SECONDS

    for _ in range(auth.AUTH_RATE_LIMITS["login"]):
        assert client.post(
            "/auth/login",
            json={"email": "missing@example.com", "password": "a-secure-password-123"},
        ).status_code == 401
    limited_login = client.post(
        "/auth/login",
        json={"email": "missing@example.com", "password": "a-secure-password-123"},
    )
    assert limited_login.status_code == 429


def test_rate_limit_retry_after_reports_remaining_window(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    timestamp = [100.0]
    monkeypatch.setattr(security_services.time, "monotonic", lambda: timestamp[0])
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/auth/register",
            "raw_path": b"/auth/register",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("testserver", 80),
        }
    )
    for _ in range(auth.AUTH_RATE_LIMITS["register"]):
        auth._enforce_auth_rate_limit(request, "register")

    timestamp[0] = 159.0
    with pytest.raises(HTTPException) as error:
        auth._enforce_auth_rate_limit(request, "register")

    assert error.value.headers["Retry-After"] == "1"


def test_forgot_password_is_generic_and_reset_revokes_sessions(
    client: TestClient, email_outbox: list[tuple[str, str, str]]
) -> None:
    register(client, "taylor@example.com", email_outbox)
    known = client.post("/auth/forgot-password", json={"email": "taylor@example.com"})
    unknown = client.post("/auth/forgot-password", json={"email": "unknown@example.com"})
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json()

    reset_link = next(word for word in email_outbox[-1][2].split() if word.startswith("http"))
    reset_token = parse_qs(urlparse(reset_link).fragment)["reset"][0]
    reset = client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": "another-secure-password-456"},
    )
    assert reset.status_code == 204
    assert client.get("/auth/me").status_code == 401
    assert client.post(
        "/auth/reset-password",
        json={"token": reset_token, "new_password": "another-secure-password-456"},
    ).status_code == 400
    assert client.post(
        "/auth/login",
        json={"email": "taylor@example.com", "password": "a-secure-password-123"},
    ).status_code == 401
    assert client.post(
        "/auth/login",
        json={"email": "taylor@example.com", "password": "another-secure-password-456"},
    ).status_code == 200


def test_login_cannot_create_session_with_a_password_invalidated_midflight(
    client: TestClient,
    email_outbox: list[tuple[str, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    register(client, "racing@example.com", email_outbox)
    csrf_token = client.get("/auth/csrf").json()["csrf_token"]
    client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    original_verify = auth.verify_password

    def verify_after_concurrent_reset(password: str, password_hash: str) -> bool:
        matched = original_verify(password, password_hash)
        with client.app.state.test_session_factory() as db:
            user = db.scalar(select(auth.User).where(auth.User.email == "racing@example.com"))
            user.password_hash = auth.hash_password("concurrently-reset-password-789")
            user.credential_version += 1
            db.commit()
        return matched

    monkeypatch.setattr(auth, "verify_password", verify_after_concurrent_reset)
    response = client.post(
        "/auth/login",
        json={"email": "racing@example.com", "password": "a-secure-password-123"},
    )

    assert response.status_code == 401
    assert client.get("/auth/me").status_code == 401


def test_unverified_password_account_cannot_login(client: TestClient, email_outbox: list[tuple[str, str, str]]) -> None:
    response = client.post(
        "/auth/register",
        json={"email": "unverified@example.com", "password": "a-secure-password-123"},
    )
    assert response.status_code == 201
    assert client.post(
        "/auth/login",
        json={"email": "unverified@example.com", "password": "a-secure-password-123"},
    ).status_code == 401


def test_email_verification_challenge_expires(client: TestClient, email_outbox, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "CHALLENGE_TTL", timedelta(seconds=-1))
    response = client.post(
        "/auth/register",
        json={"email": "expired@example.com", "password": "a-secure-password-123"},
    )
    link = next(word for word in email_outbox[-1][2].split() if word.startswith("http"))
    token = parse_qs(urlparse(link).fragment)["verify"][0]

    assert response.status_code == 201
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400


def test_master_cv_saves_revisions_and_is_user_scoped(
    client: TestClient, email_outbox: list[tuple[str, str, str]]
) -> None:
    first = register(client, "first@example.com", email_outbox)
    initial = client.get("/master-cv/me")
    assert initial.status_code == 200
    assert initial.json()["version"] == 0

    cv_content = {
        "contact": {"full_name": "Taylor Example", "email": "first@example.com"},
        "professional_summary": "Experienced project coordinator.",
        "employment": [
            {
                "job_title": "Coordinator",
                "employer": "Example Ltd",
                "achievements": ["Delivered projects on time"],
            }
        ],
        "skills": ["Planning", "Communication"],
    }
    saved = client.put(
        "/master-cv/me",
        headers={"X-CSRF-Token": first["csrf_token"]},
        json={"expected_version": 0, "content": cv_content},
    )
    assert saved.status_code == 200
    assert saved.json()["version"] == 1
    updated_content = {**cv_content, "professional_summary": "Experienced delivery manager."}
    updated = client.put(
        "/master-cv/me",
        headers={"X-CSRF-Token": first["csrf_token"]},
        json={"expected_version": 1, "content": updated_content},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    stale = client.put(
        "/master-cv/me",
        headers={"X-CSRF-Token": first["csrf_token"]},
        json={"expected_version": 0, "content": cv_content},
    )
    assert stale.status_code == 409
    revisions = client.get("/master-cv/revisions/me").json()
    assert [revision["version"] for revision in revisions] == [2, 1]
    assert revisions[1]["content"]["professional_summary"] == "Experienced project coordinator."
    assert client.delete("/master-cv/me").status_code == 403
    assert client.delete(
        "/master-cv/me",
        headers={"X-CSRF-Token": first["csrf_token"]},
    ).status_code == 204
    assert client.get("/master-cv/revisions/me").json() == []

    client.post("/auth/logout", headers={"X-CSRF-Token": first["csrf_token"]})
    register(client, "second@example.com", email_outbox)
    other_user_cv = client.get("/master-cv/me").json()
    assert other_user_cv["version"] == 0
    assert other_user_cv["content"]["professional_summary"] == ""


def test_master_cv_requires_role_permission(
    client: TestClient, email_outbox: list[tuple[str, str, str]]
) -> None:
    user = register(client, "role@example.com", email_outbox)
    with client.app.state.test_session_factory() as db:
        account = db.get(User, user["id"])
        account.role = "unassigned"
        db.commit()

    assert client.get("/master-cv/me").status_code == 403


def test_master_cv_policy_requires_matching_owner() -> None:
    with pytest.raises(HTTPException) as denied:
        authorize_resource_access(
            role="candidate",
            subject_id="candidate-1",
            owner_id="candidate-2",
            permission="master_cv:read",
        )

    assert denied.value.status_code == 404


def test_oversized_request_body_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/auth/register",
        content=b"x" * (1024 * 1024 + 1),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413


def test_oidc_signin_creates_separate_identity_without_email_autolinking(
    client: TestClient,
    email_outbox: list[tuple[str, str, str]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = {
        "iss": "https://issuer.example",
        "sub": "provider-user-1",
        "email": "external@example.com",
        "email_verified": True,
        "name": "External User",
    }

    class FakeOIDCClient:
        async def authorize_access_token(self, request):
            return {"userinfo": claims}

    monkeypatch.setenv("APP_SECRET_KEY", "a" * 48)
    monkeypatch.setattr(auth, "_oidc_client", lambda provider: FakeOIDCClient())
    response = client.get("/auth/oauth/oidc/callback", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/static/account.html?oauth=success"
    assert client.get("/auth/me").json()["email"] == "external@example.com"

    existing = register(client, "collision@example.com", email_outbox)
    claims.update(sub="provider-user-2", email="collision@example.com")
    duplicate_identity = client.get(
        "/auth/oauth/oidc/callback",
        follow_redirects=False,
    )
    assert duplicate_identity.status_code == 409
    assert client.get("/auth/me").json()["id"] == existing["id"]


def test_oidc_providers_are_enabled_only_when_fully_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "google-secret")
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "microsoft-client")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "microsoft-secret")
    monkeypatch.setenv("MICROSOFT_TENANT_ID", "tenant-id")
    monkeypatch.setenv("OIDC_CLIENT_ID", "other-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "other-secret")
    monkeypatch.setenv("OIDC_DISCOVERY_URL", "https://id.example/.well-known/openid-configuration")

    assert auth.oauth_providers()["providers"] == ["google", "microsoft", "oidc"]


def test_redis_rate_limit_is_shared_and_does_not_store_email(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeRedis:
        def __init__(self) -> None:
            self.counts: dict[str, int] = {}
            self.keys: list[str] = []

        def eval(self, script, key_count, key, window):
            self.keys.append(key)
            self.counts[key] = self.counts.get(key, 0) + 1
            return self.counts[key], window

    fake = FakeRedis()
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("REDIS_URL", "redis://shared-test")
    monkeypatch.setattr(security_services, "_redis_clients", {"redis://shared-test": fake})

    for _ in range(security_services.RATE_LIMITS["register"]):
        security_services.enforce_rate_limit("register", "203.0.113.5", "private@example.com")
    with pytest.raises(HTTPException) as error:
        security_services.enforce_rate_limit("register", "203.0.113.5", "private@example.com")

    assert error.value.status_code == 429
    assert fake.keys
    assert all("private@example.com" not in key for key in fake.keys)


def test_production_requires_shared_rate_limiter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("REDIS_URL", raising=False)

    with pytest.raises(HTTPException) as error:
        security_services.enforce_rate_limit("login", "203.0.113.9")

    assert error.value.status_code == 503


def test_oauth_redirect_requires_https_or_exact_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OAUTH_REDIRECT_BASE_URL", "http://localhost.attacker.test")
    with pytest.raises(HTTPException):
        auth._oauth_redirect_uri("google")
    monkeypatch.setenv("OAUTH_REDIRECT_BASE_URL", "https://resumint.core456.com")
    assert auth._oauth_redirect_uri("google") == "https://resumint.core456.com/auth/oauth/google/callback"


def test_oauth_start_uses_configured_callback_and_signed_state(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeOIDCClient:
        async def authorize_redirect(self, request, redirect_uri):
            from starlette.responses import RedirectResponse

            assert redirect_uri == "https://resumint.core456.com/auth/oauth/google/callback"
            request.session["state"] = "signed-by-session-middleware"
            return RedirectResponse("https://accounts.example/authorize", status_code=302)

    monkeypatch.setenv("APP_SECRET_KEY", "a" * 48)
    monkeypatch.setenv("OAUTH_REDIRECT_BASE_URL", "https://resumint.core456.com")
    monkeypatch.setattr(auth, "_oidc_client", lambda provider: FakeOIDCClient())
    response = client.get("/auth/oauth/google", follow_redirects=False)

    assert response.status_code == 302
    assert response.headers["location"] == "https://accounts.example/authorize"
    assert "resumint_oauth_state" in response.cookies


def test_production_host_configuration_is_validated(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.app import validate_production_config

    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("APP_SECRET_KEY", "s" * 48)
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://localhost/resumint")
    monkeypatch.setenv("REDIS_URL", "rediss://redis.internal:6379/0")
    monkeypatch.setenv("SMTP_HOST", "smtp.mail.test")
    monkeypatch.setenv("EMAIL_FROM", "no-reply@resumint.core456.com")
    monkeypatch.setenv("POSTGRES_PASSWORD", "a-strong-password")
    monkeypatch.setenv("PUBLIC_APP_URL", "https://resumint.core456.com")
    monkeypatch.setenv("OAUTH_REDIRECT_BASE_URL", "https://resumint.core456.com")
    validate_production_config()
    monkeypatch.setenv("PUBLIC_APP_URL", "https://other.example.net")
    with pytest.raises(RuntimeError):
        validate_production_config()


def test_resumint_home_and_public_legacy_activity_demo_remain_available(client: TestClient) -> None:
    home = client.get("/")
    legacy = client.get("/legacy")
    activities = client.get("/activities")

    assert home.status_code == 200 and "ResuMint" in home.text
    assert legacy.status_code == 200 and "Mergington High School" in legacy.text
    assert activities.status_code == 200
