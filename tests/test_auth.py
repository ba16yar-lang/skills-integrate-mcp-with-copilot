from collections.abc import Iterator

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src import auth
from src.app import app
from src.database import Base, get_db


@pytest.fixture
def client() -> Iterator[TestClient]:
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
        yield test_client
    app.dependency_overrides.clear()
    Base.metadata.drop_all(engine)
    engine.dispose()
    with auth._auth_attempts_lock:
        auth._auth_attempts.clear()


def register(client: TestClient, email: str) -> dict:
    response = client.post(
        "/auth/register",
        json={"email": email, "password": "a-secure-password-123", "full_name": "Taylor Example"},
    )
    assert response.status_code == 201
    return response.json()


def test_registration_normalizes_email_and_authenticates(client: TestClient) -> None:
    result = register(client, " Taylor@Example.com ")

    assert result["email"] == "taylor@example.com"
    assert client.cookies.get("core456_session")
    assert client.get("/auth/me").json()["id"] == result["id"]
    assert client.get("/profile/me").json()["full_name"] == "Taylor Example"


def test_duplicate_registration_and_weak_password_are_rejected(client: TestClient) -> None:
    register(client, "taylor@example.com")
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


def test_login_logout_and_revocation(client: TestClient) -> None:
    register(client, "taylor@example.com")
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


def test_profile_updates_require_csrf_and_are_user_scoped(client: TestClient) -> None:
    first = register(client, "first@example.com")
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
    register(client, "second@example.com")
    own_profile = client.get("/profile/me").json()
    assert own_profile["email"] == "second@example.com"
    assert own_profile["full_name"] == "Taylor Example"


def test_invalid_login_does_not_authenticate(client: TestClient) -> None:
    register(client, "taylor@example.com")
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

    client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": client.get("/auth/csrf").json()["csrf_token"]},
    )
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


def test_rate_limit_retry_after_reports_remaining_window(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    timestamp = [100.0]
    monkeypatch.setattr(auth.time, "monotonic", lambda: timestamp[0])
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
