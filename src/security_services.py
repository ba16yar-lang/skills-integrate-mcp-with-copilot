import hashlib
import hmac
import os
import smtplib
import threading
import time
from collections import OrderedDict, deque
from email.message import EmailMessage
from math import ceil

from fastapi import HTTPException, status


RATE_WINDOW_SECONDS = 60
RATE_LIMITS = {
    "register": 5,
    "login": 10,
    "verify_request": 3,
    "verify_email": 5,
    "password_reset_request": 3,
    "password_reset": 5,
    "oauth_start": 20,
    "oauth_callback": 30,
}
MAX_RATE_LIMIT_CLIENTS = 4096
_attempts: OrderedDict[tuple[str, str], tuple[deque[float], float]] = OrderedDict()
_attempts_lock = threading.Lock()
_redis_clients = {}
_redis_clients_lock = threading.Lock()
_REDIS_WINDOW_SCRIPT = """
local count = redis.call('INCR', KEYS[1])
if count == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return {count, ttl}
"""


def get_redis_client(url: str):
    from redis import Redis

    with _redis_clients_lock:
        client = _redis_clients.get(url)
        if client is None:
            client = Redis.from_url(url, socket_connect_timeout=1, socket_timeout=1)
            _redis_clients[url] = client
        return client


def _limited(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests. Try again later.",
        headers={"Retry-After": str(max(1, retry_after))},
    )


def _local_check(key: tuple[str, str], limit: int, now: float) -> None:
    cutoff = now - RATE_WINDOW_SECONDS
    with _attempts_lock:
        while _attempts:
            oldest_key, (_, last_seen) = next(iter(_attempts.items()))
            if last_seen > cutoff:
                break
            _attempts.pop(oldest_key)

        attempts, _ = _attempts.get(key, (deque(), now))
        while attempts and attempts[0] <= cutoff:
            attempts.popleft()
        if len(attempts) >= limit:
            raise _limited(ceil(attempts[0] + RATE_WINDOW_SECONDS - now))
        attempts.append(now)
        _attempts[key] = (attempts, now)
        _attempts.move_to_end(key)
        while len(_attempts) > MAX_RATE_LIMIT_CLIENTS:
            _attempts.popitem(last=False)


def _redis_check(url: str, action: str, dimension: str, identifier: str, limit: int) -> None:
    client = get_redis_client(url)
    secret = os.getenv("APP_SECRET_KEY", "local-rate-limit")
    digest = hmac.new(secret.encode(), identifier.encode(), hashlib.sha256).hexdigest()
    result = client.eval(
        _REDIS_WINDOW_SCRIPT,
        1,
        f"core456:rate:{action}:{dimension}:{digest}",
        RATE_WINDOW_SECONDS,
    )
    count, ttl = int(result[0]), int(result[1])
    if count > limit:
        raise _limited(ttl)


def enforce_rate_limit(action: str, client_host: str, identifier: str | None = None) -> None:
    limit = RATE_LIMITS[action]
    redis_url = os.getenv("REDIS_URL")
    production = os.getenv("ENVIRONMENT", "").casefold() == "production"
    if production and not redis_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Shared rate limiting is not configured",
        )

    now = time.monotonic()
    if redis_url:
        try:
            _redis_check(redis_url, action, "ip", client_host, limit)
            if identifier:
                _redis_check(redis_url, action, "identity", identifier.casefold(), limit)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limiting is temporarily unavailable",
            ) from exc
        return

    _local_check((action, f"ip:{client_host}"), limit, now)
    if identifier:
        digest = hashlib.sha256(identifier.casefold().encode()).hexdigest()
        _local_check((action, f"identity:{digest}"), limit, now)


def send_account_email(recipient: str, subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    sender = os.getenv("EMAIL_FROM")
    if not host or not sender:
        raise RuntimeError("Email delivery is not configured")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    port = int(os.getenv("SMTP_PORT", "587"))
    username = os.getenv("SMTP_USERNAME")
    password = os.getenv("SMTP_PASSWORD")
    timeout = 10
    if os.getenv("SMTP_SSL", "").casefold() in {"1", "true", "yes"}:
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as smtp:
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.ehlo()
            if os.getenv("SMTP_STARTTLS", "true").casefold() in {"1", "true", "yes"}:
                smtp.starttls()
                smtp.ehlo()
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
