from contextlib import asynccontextmanager
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from src.auth import profile_router, router as auth_router
from src.cv import router as master_cv_router
from src.database import engine
from src.security_services import RATE_LIMITS, get_redis_client


PRODUCTION_HOST = "resumint.core456.com"
MAX_REQUEST_BODY_BYTES = 1024 * 1024


class RequestBodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            content_length = 0
        if content_length > self.max_bytes:
            await self._reject(send)
            return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestBodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            await self._reject(send)

    @staticmethod
    async def _reject(send):
        body = b'{"detail":"Request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def validate_production_config() -> None:
    if os.getenv("ENVIRONMENT", "").casefold() != "production":
        return
    required = (
        "APP_SECRET_KEY",
        "DATABASE_URL",
        "REDIS_URL",
        "SMTP_HOST",
        "EMAIL_FROM",
        "POSTGRES_PASSWORD",
    )
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError(f"Missing production configuration: {', '.join(missing)}")
    if len(os.environ["APP_SECRET_KEY"]) < 32 or "replace-with" in os.environ["APP_SECRET_KEY"].casefold():
        raise RuntimeError("APP_SECRET_KEY must contain at least 32 characters")
    if "replace-with" in os.environ["DATABASE_URL"].casefold() or "replace-with" in os.environ["POSTGRES_PASSWORD"].casefold():
        raise RuntimeError("Replace deployment placeholders with real database credentials")
    if os.environ["SMTP_HOST"].casefold().endswith(".example.net"):
        raise RuntimeError("Configure a real SMTP host before production startup")
    if not os.environ["DATABASE_URL"].startswith("postgresql+psycopg://"):
        raise RuntimeError("Production DATABASE_URL must use postgresql+psycopg")
    redis_url = urlsplit(os.environ["REDIS_URL"])
    if redis_url.scheme not in {"redis", "rediss"} or not redis_url.hostname:
        raise RuntimeError("Production REDIS_URL must use Redis")
    if redis_url.scheme == "redis" and redis_url.hostname != "redis":
        raise RuntimeError("External production Redis must use TLS (rediss://)")
    for key in ("PUBLIC_APP_URL", "OAUTH_REDIRECT_BASE_URL"):
        if os.getenv(key, "").rstrip("/") != f"https://{PRODUCTION_HOST}":
            raise RuntimeError(f"{key} must be https://{PRODUCTION_HOST}")
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError as exc:
        raise RuntimeError("SMTP_PORT must be a valid port number") from exc
    if not 1 <= port <= 65535:
        raise RuntimeError("SMTP_PORT must be a valid port number")
    if (
        os.getenv("SMTP_SSL", "").casefold() not in {"1", "true", "yes"}
        and os.getenv("SMTP_STARTTLS", "true").casefold() not in {"1", "true", "yes"}
    ):
        raise RuntimeError("Production email delivery must use SMTP SSL or STARTTLS")
    if bool(os.getenv("SMTP_USERNAME")) != bool(os.getenv("SMTP_PASSWORD")):
        raise RuntimeError("SMTP_USERNAME and SMTP_PASSWORD must be configured together")


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_production_config()
    if os.getenv("ENVIRONMENT", "").casefold() == "production":
        with engine.connect() as connection:
            current_head = ScriptDirectory.from_config(Config("src/alembic.ini")).get_current_head()
            try:
                installed = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            except Exception as exc:
                raise RuntimeError("Database migrations are missing; run Alembic upgrade before startup") from exc
            if installed != current_head:
                raise RuntimeError(f"Database migration {installed} does not match application head {current_head}")
        get_redis_client(os.environ["REDIS_URL"]).ping()
    yield

app = FastAPI(
    title="ResuMint Career Intelligence API",
    description="Career platform account API and legacy Mergington activities example",
    docs_url=None if os.getenv("ENVIRONMENT", "").casefold() == "production" else "/docs",
    redoc_url=None if os.getenv("ENVIRONMENT", "").casefold() == "production" else "/redoc",
    openapi_url=None if os.getenv("ENVIRONMENT", "").casefold() == "production" else "/openapi.json",
    lifespan=lifespan,
)
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(master_cv_router)
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("APP_SECRET_KEY") or secrets.token_urlsafe(32),
    session_cookie="resumint_oauth_state",
    same_site="lax",
    https_only=os.getenv("ENVIRONMENT", "").casefold() == "production",
)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)
if os.getenv("ENVIRONMENT", "").casefold() == "production":
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=[PRODUCTION_HOST]
    if os.getenv("ENVIRONMENT", "").casefold() == "production"
    else [PRODUCTION_HOST, "localhost", "127.0.0.1", "testserver"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
    )
    if os.getenv("ENVIRONMENT", "").casefold() == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith(("/auth", "/profile", "/master-cv")):
        response.headers["Cache-Control"] = "no-store"
    return response

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": ["michael@mergington.edu", "daniel@mergington.edu"]
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": ["emma@mergington.edu", "sophia@mergington.edu"]
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": ["john@mergington.edu", "olivia@mergington.edu"]
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": ["liam@mergington.edu", "noah@mergington.edu"]
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["ava@mergington.edu", "mia@mergington.edu"]
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": ["amelia@mergington.edu", "harper@mergington.edu"]
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": ["ella@mergington.edu", "scarlett@mergington.edu"]
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": ["james@mergington.edu", "benjamin@mergington.edu"]
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": ["charlotte@mergington.edu", "henry@mergington.edu"]
    }
}


@app.get("/")
def root():
    return RedirectResponse(url="/static/account.html")


@app.get("/legacy")
def legacy_demo():
    return RedirectResponse(url="/static/index.html")


@app.get("/health/live")
def health_live():
    return {"status": "ok"}


@app.get("/health/ready")
def health_ready():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        if os.getenv("ENVIRONMENT", "").casefold() == "production":
            get_redis_client(os.environ["REDIS_URL"]).ping()
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Service dependencies are unavailable") from exc
    return {"status": "ready", "rate_limit_actions": len(RATE_LIMITS)}


@app.get("/activities")
def get_activities():
    return activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str):
    """Sign up a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is not already signed up
    if email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up"
        )

    # Add student
    activity["participants"].append(email)
    return {"message": f"Signed up {email} for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str):
    """Unregister a student from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Validate student is signed up
    if email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(email)
    return {"message": f"Unregistered {email} from {activity_name}"}
