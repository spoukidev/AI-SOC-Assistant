"""Single-admin authentication for the API (Milestone 5).

* The admin account comes from environment variables. ``ADMIN_PASSWORD_HASH`` (PBKDF2-SHA256,
  generate with ``python -m app.auth hash-password``) is preferred; ``ADMIN_PASSWORD`` is hashed
  in memory at startup. If neither is set a random password is generated and logged once.
* Access tokens are short-lived HS256 JWTs signed with ``AUTH_SECRET_KEY``. If it is unset a random
  key is generated per process, so tokens stop working after a restart.
* Password and username checks use constant-time comparison, and repeated failures are throttled.
* Browsers authenticate with an HttpOnly, SameSite=Strict session cookie (Secure unless
  AUTH_COOKIE_SECURE=false). Every token carries a random ``csrf`` claim; cookie-authenticated
  POST/PATCH/PUT/DELETE requests must echo it in ``X-CSRF-Token`` (the UI reads it from
  ``GET /api/auth/me``, which cross-origin pages cannot read because of CORS). Requests sent with an
  ``Authorization: Bearer`` header (scripts) are not exposed to CSRF and skip that check.
"""
from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import logging
import secrets
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, settings

logger = logging.getLogger("app.auth")

PBKDF2_ITERATIONS = 600_000
TOKEN_ALGORITHM = "HS256"
TOKEN_ISSUER = "soc-xai"
MIN_SECRET_LENGTH = 32
MAX_FAILURES = 5
FAILURE_WINDOW_SECONDS = 300


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    encode = lambda raw: base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")  # noqa: E731
    return f"pbkdf2_sha256:{iterations}:{encode(salt)}:{encode(digest)}"


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split(":")
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _decode(salt), int(iterations))
        return hmac.compare_digest(digest, _decode(expected))
    except (ValueError, TypeError):
        return False


@dataclass
class AuthConfig:
    username: str
    password_hash: str
    secret_key: str
    ttl: timedelta
    generated_password: bool = False
    generated_secret: bool = False


def build_auth_config(config: Settings) -> AuthConfig:
    generated_password = generated_secret = False
    if config.admin_password_hash:
        password_hash = config.admin_password_hash
    elif config.admin_password:
        password_hash = hash_password(config.admin_password)
    else:
        password = secrets.token_urlsafe(18)
        password_hash = hash_password(password)
        generated_password = True
        logger.warning(
            "ADMIN_PASSWORD / ADMIN_PASSWORD_HASH is not set. Generated a one-time admin password for user %r: %s "
            "(set ADMIN_PASSWORD_HASH to keep a stable password)", config.admin_username, password,
        )
    secret = config.auth_secret_key
    if not secret:
        secret = secrets.token_urlsafe(48)
        generated_secret = True
        logger.warning("AUTH_SECRET_KEY is not set. Generated a per-process signing key; tokens will not survive a restart.")
    elif len(secret) < MIN_SECRET_LENGTH:
        raise RuntimeError(f"AUTH_SECRET_KEY must be at least {MIN_SECRET_LENGTH} characters")
    ttl = timedelta(minutes=max(1, min(config.access_token_ttl_minutes, 24 * 60)))
    return AuthConfig(config.admin_username, password_hash, secret, ttl, generated_password, generated_secret)


_auth_config: AuthConfig | None = None
_config_lock = threading.Lock()


def get_auth_config() -> AuthConfig:
    global _auth_config
    with _config_lock:
        if _auth_config is None:
            _auth_config = build_auth_config(settings)
        return _auth_config


class LoginThrottle:
    """In-memory failed-login limiter keyed by client address (per process)."""

    def __init__(self, max_failures: int = MAX_FAILURES, window_seconds: int = FAILURE_WINDOW_SECONDS):
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        recent = [moment for moment in self._failures.get(key, []) if now - moment < self.window]
        if recent:
            self._failures[key] = recent
        else:
            self._failures.pop(key, None)
        return recent

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self.max_failures

    def fail(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._recent(key, now)
            self._failures.setdefault(key, []).append(now)

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._failures.clear()
            else:
                self._failures.pop(key, None)


login_throttle = LoginThrottle()


def authenticate(username: str, password: str) -> bool:
    config = get_auth_config()
    # Always run the password hash so timing does not reveal whether the username matched.
    password_ok = verify_password(password, config.password_hash)
    username_ok = hmac.compare_digest(username.encode("utf-8"), config.username.encode("utf-8"))
    return password_ok and username_ok


SESSION_COOKIE = "soc_xai_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class IssuedToken:
    token: str
    expires_in: int
    csrf_token: str


def create_access_token(subject: str, config: AuthConfig | None = None) -> IssuedToken:
    config = config or get_auth_config()
    now = datetime.now(timezone.utc)
    csrf = secrets.token_urlsafe(32)
    claims = {"sub": subject, "iss": TOKEN_ISSUER, "iat": now, "nbf": now, "exp": now + config.ttl,
              "jti": secrets.token_hex(8), "csrf": csrf}
    token = jwt.encode(claims, config.secret_key, algorithm=TOKEN_ALGORITHM)
    return IssuedToken(token, int(config.ttl.total_seconds()), csrf)


def decode_access_token(token: str) -> dict:
    config = get_auth_config()
    return jwt.decode(
        token, config.secret_key, algorithms=[TOKEN_ALGORITHM], issuer=TOKEN_ISSUER,
        options={"require": ["exp", "iat", "sub", "iss"]},
    )


_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated", headers={"WWW-Authenticate": "Bearer"},
)


def _origin_allowed(request: Request) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True
    same_origin = f"{request.url.scheme}://{request.url.netloc}"
    return origin == same_origin or origin in settings.cors_origins


def require_user(request: Request, credentials: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    from_cookie = False
    if credentials is not None and credentials.scheme.lower() == "bearer" and credentials.credentials:
        token = credentials.credentials
    elif request.cookies.get(SESSION_COOKIE):
        token, from_cookie = request.cookies[SESSION_COOKIE], True
    else:
        raise _UNAUTHORIZED
    try:
        claims = decode_access_token(token)
    except jwt.PyJWTError:
        raise _UNAUTHORIZED from None
    if not hmac.compare_digest(str(claims["sub"]).encode("utf-8"), get_auth_config().username.encode("utf-8")):
        raise _UNAUTHORIZED
    if from_cookie and request.method.upper() not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER, "")
        expected = str(claims.get("csrf") or "")
        if not expected or not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid")
        if not _origin_allowed(request):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Cross-origin request rejected")
    request.state.user = claims["sub"]
    request.state.claims = claims
    return claims["sub"]


def _main(argv: list[str]) -> int:
    if argv[:1] != ["hash-password"]:
        print("usage: python -m app.auth hash-password", file=sys.stderr)
        return 2
    password = getpass.getpass("Admin password: ")
    if len(password) < 12:
        print("Use at least 12 characters.", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat password: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    print(hash_password(password))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
