"""Every checkpoint from the brief, run against a FAKE identity provider.

The fake behaves like Supabase from the routes' point of view (same 6 methods, same exceptions), so these tests
check OUR code: validation, status codes, the guard, the 401/403 split, rate limiting. They do not test Supabase
itself; that is what the manual curl run in the README is for.
"""
import pytest
from fastapi.testclient import TestClient

import main
from auth_provider import AuthFailed, InvalidToken, get_auth


class FakeAuth:
    def __init__(self):
        self.users = {}          # email -> password
        self.tokens = {}         # access token -> email
        self.revoked = set()

    def sign_up(self, email, password):
        if email in self.users:
            raise AuthFailed("User already registered")
        if len(password) < 6:
            raise AuthFailed("Password should be at least 6 characters.")
        self.users[email] = password
        return {"id": f"uid-{email}", "email": email}

    def sign_in(self, email, password):
        if self.users.get(email) != password:
            raise AuthFailed("bad")
        token = f"tok-{email}-{len(self.tokens)}"
        self.tokens[token] = email
        return {"access_token": token, "refresh_token": f"ref-{token}", "token_type": "bearer", "expires_in": 3600}

    def get_user(self, token):
        email = self.tokens.get(token)
        if not email or token in self.revoked:
            raise InvalidToken()
        return {"id": f"uid-{email}", "email": email, "created_at": "2026-10-22T00:00:00+00:00",
                "role": "admin" if email.startswith("boss") else "user"}

    def refresh(self, refresh_token):
        old = refresh_token.removeprefix("ref-")
        if old not in self.tokens:
            raise InvalidToken()
        return self.sign_in(self.tokens[old], self.users[self.tokens[old]])

    def sign_out(self, token):
        self.revoked.add(token)


@pytest.fixture()
def client():
    fake = FakeAuth()
    main.app.dependency_overrides[get_auth] = lambda: fake
    main._failed.clear()
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def login(client, email="test@example.com", password="password123"):
    client.post("/auth/signup", json={"email": email, "password": password})
    return client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


def test_signup_201_and_missing_password_400(client):
    r = client.post("/auth/signup", json={"email": "test@example.com", "password": "password123"})
    assert r.status_code == 201 and r.json()["user"]["email"] == "test@example.com"
    r = client.post("/auth/signup", json={"email": "x@example.com"})
    assert r.status_code == 400 and "password" in r.json()["error"]


def test_signup_rejected_by_provider_is_400(client):
    client.post("/auth/signup", json={"email": "a@example.com", "password": "password123"})
    r = client.post("/auth/signup", json={"email": "a@example.com", "password": "password123"})
    assert r.status_code == 400 and r.json() == {"error": "User already registered"}


def test_login_returns_tokens_or_401(client):
    client.post("/auth/signup", json={"email": "test@example.com", "password": "password123"})
    r = client.post("/auth/login", json={"email": "test@example.com", "password": "password123"})
    assert r.status_code == 200 and r.json()["access_token"] and r.json()["refresh_token"]
    r = client.post("/auth/login", json={"email": "test@example.com", "password": "nope"})
    assert r.status_code == 401 and r.json() == {"error": "Invalid login credentials"}
    assert client.post("/auth/login", json={"email": "test@example.com"}).status_code == 400


def test_unconfirmed_email_gets_a_clear_403(client):
    from auth_provider import EmailNotConfirmed
    from main import app
    from auth_provider import get_auth

    class Unconfirmed:
        def sign_in(self, email, password):
            raise EmailNotConfirmed("Email not confirmed")

    app.dependency_overrides[get_auth] = lambda: Unconfirmed()
    try:
        r = client.post("/auth/login", json={"email": "new@example.com", "password": "password123"})
    finally:
        app.dependency_overrides.pop(get_auth, None)
    assert r.status_code == 403 and "Email not confirmed" in r.json()["error"]


def test_public_is_open(client):
    r = client.get("/public/info")
    assert r.status_code == 200 and r.json() == {"message": "Welcome stranger! This info is public."}


@pytest.mark.parametrize("headers", [{}, {"Authorization": "abc"}, {"Authorization": "Bearer "},
                                     {"Authorization": "Basic dXNlcjpwYXNz"}])
def test_missing_or_malformed_header_is_401(client, headers):
    r = client.get("/protected/profile", headers=headers)
    assert r.status_code == 401 and r.json() == {"error": "Access token required"}


def test_valid_token_200_and_tampered_token_401(client):
    t = login(client)
    r = client.get("/protected/profile", headers=bearer(t))
    assert r.status_code == 200 and r.json()["email"] == "test@example.com"
    assert set(r.json()) == {"id", "email", "created_at"}  # no tokens or secrets echoed back
    r = client.get("/protected/profile", headers=bearer(t[:-1] + "X"))
    assert r.status_code == 401 and r.json() == {"error": "Invalid or expired token"}


def test_same_guard_on_a_second_route(client):
    t = login(client)
    assert client.get("/protected/dashboard", headers=bearer(t)).status_code == 200
    assert client.get("/protected/dashboard", headers=bearer("forged")).status_code == 401


def test_logout_204_then_token_rejected(client):
    t = login(client)
    r = client.post("/auth/logout", headers=bearer(t))
    assert r.status_code == 204 and r.content == b""
    assert client.post("/auth/logout").status_code == 401


def test_401_vs_403(client):
    user_t = login(client)
    boss_t = login(client, email="boss@example.com")
    assert client.get("/protected/admin").status_code == 401
    assert client.get("/protected/admin", headers=bearer(user_t)).status_code == 403
    assert client.get("/protected/admin", headers=bearer(boss_t)).status_code == 200


def test_refresh_flow(client):
    client.post("/auth/signup", json={"email": "r@example.com", "password": "password123"})
    tokens = client.post("/auth/login", json={"email": "r@example.com", "password": "password123"}).json()
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200 and r.json()["access_token"] != tokens["access_token"]
    assert client.post("/auth/refresh", json={"refresh_token": "junk"}).status_code == 401


def test_rate_limit_after_5_failures(client):
    client.post("/auth/signup", json={"email": "v@example.com", "password": "password123"})
    for _ in range(5):
        assert client.post("/auth/login", json={"email": "v@example.com", "password": "x"}).status_code == 401
    r = client.post("/auth/login", json={"email": "v@example.com", "password": "password123"})
    assert r.status_code == 429 and r.headers["Retry-After"] == "900"


def test_swagger_shows_bearer_lock_on_protected_routes(client):
    spec = client.get("/openapi.json").json()
    assert spec["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"
    assert spec["paths"]["/protected/profile"]["get"]["security"] == [{"HTTPBearer": []}]
    assert "security" not in spec["paths"]["/public/info"]["get"]
