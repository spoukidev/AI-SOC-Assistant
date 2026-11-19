import os

# Test-only credentials. They are set before the app (and its Settings) are imported.
os.environ.setdefault("AUTH_SECRET_KEY", "test-only-signing-key-0123456789abcdef-not-for-production")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "test-only-admin-password")

TEST_ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
TEST_ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]


def auth_headers() -> dict[str, str]:
    from app.auth import create_access_token

    return {"Authorization": f"Bearer {create_access_token(TEST_ADMIN_USERNAME).token}"}
