"""Talks to Supabase Auth (the Identity Provider). This file is the only place that knows Supabase exists."""
from __future__ import annotations

import os

from dotenv import load_dotenv
from supabase import Client, ClientOptions, create_client

load_dotenv()

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")


def new_client() -> Client:
    """A fresh client per call. persist_session=False so one user's session can never leak into another request."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
    return create_client(SUPABASE_URL, SUPABASE_KEY,
                         options=ClientOptions(persist_session=False, auto_refresh_token=False))


class AuthFailed(Exception):
    """Supabase rejected the request (bad credentials, existing user, weak password...)."""


class EmailNotConfirmed(AuthFailed):
    """Right password, but Supabase's "Confirm email" is on and this address was never confirmed."""


class InvalidToken(Exception):
    """The access token is expired, tampered with, or not a Supabase token."""


class SupabaseAuth:
    """Thin wrapper so routes depend on 4-5 plain methods, and tests can swap in a fake."""

    def sign_up(self, email: str, password: str) -> dict:
        try:
            res = new_client().auth.sign_up({"email": email, "password": password})
        except Exception as exc:  # supabase_auth.errors.AuthApiError and friends
            raise AuthFailed(getattr(exc, "message", str(exc))) from exc
        return res.user.model_dump(mode="json")

    def sign_in(self, email: str, password: str) -> dict:
        try:
            res = new_client().auth.sign_in_with_password({"email": email, "password": password})
        except Exception as exc:
            if getattr(exc, "code", None) == "email_not_confirmed" or "not confirmed" in str(exc).lower():
                raise EmailNotConfirmed("Email not confirmed") from exc
            raise AuthFailed("Invalid login credentials") from exc
        s = res.session
        return {"access_token": s.access_token, "refresh_token": s.refresh_token,
                "token_type": "bearer", "expires_in": s.expires_in}


    def get_user(self, token: str) -> dict:
        try:
            res = new_client().auth.get_user(token)  # network call: Supabase checks signature + expiry
        except Exception as exc:
            raise InvalidToken() from exc
        if not res or not res.user:
            raise InvalidToken()
        u = res.user
        return {"id": u.id, "email": u.email,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "role": (u.app_metadata or {}).get("role", "user")}

    def refresh(self, refresh_token: str) -> dict:
        """Trade a refresh token for a new access token (no password needed)."""
        try:
            res = new_client().auth.refresh_session(refresh_token)
        except Exception as exc:
            raise InvalidToken() from exc
        s = res.session
        return {"access_token": s.access_token, "refresh_token": s.refresh_token,
                "token_type": "bearer", "expires_in": s.expires_in}

    def sign_out(self, token: str) -> None:
        """Revokes this session's refresh token at Supabase (scope=local: only this device)."""
        new_client().auth.admin.sign_out(token, "local")


def get_auth() -> SupabaseAuth:
    return SupabaseAuth()



